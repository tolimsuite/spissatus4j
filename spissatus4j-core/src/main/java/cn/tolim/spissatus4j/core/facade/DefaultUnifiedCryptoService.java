package cn.tolim.spissatus4j.core.facade;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.audit.AuditEvent;
import cn.tolim.spissatus4j.contract.audit.AuditEventType;
import cn.tolim.spissatus4j.contract.audit.AuditOutcome;
import cn.tolim.spissatus4j.contract.audit.AuditSeverity;
import cn.tolim.spissatus4j.contract.audit.MetricNames;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.DecryptRequest;
import cn.tolim.spissatus4j.contract.crypto.EncryptRequest;
import cn.tolim.spissatus4j.contract.crypto.EncryptedData;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeBinding;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.exception.AuditException;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.exception.PolicyException;
import cn.tolim.spissatus4j.contract.exception.SpissatusException;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.unified.SelectionProfile;
import cn.tolim.spissatus4j.contract.unified.SelectionReport;
import cn.tolim.spissatus4j.contract.unified.UnifiedDecryptRequest;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptRequest;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptionResult;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

/**
 * Unified encrypt/decrypt implementation.
 *
 * <p>Selection is hard-filtered without policy side effects; exactly one
 * authoritative policy decision is made by {@link DefaultCryptoService}.
 * Envelopes produced here are v2 and carry an authenticated metadata hash.</p>
 */
final class DefaultUnifiedCryptoService {

    private static final Duration MAX_FUTURE_SKEW = Duration.ofMinutes(5);

    private final FacadeContext context;
    private final DefaultCryptoService crypto;
    private final SelectionSettings settings;
    private final ProviderCapabilityIndex providers;
    private final AlgorithmSelector selector;

    DefaultUnifiedCryptoService(FacadeContext context, DefaultCryptoService crypto) {
        this.context = Objects.requireNonNull(context, "context");
        this.crypto = Objects.requireNonNull(crypto, "crypto");
        this.settings = new SelectionSettings(context.settings(), context.complianceMode());
        this.providers = ProviderCapabilityIndex.build(context);
        this.selector = new AlgorithmSelector(context, settings, providers);
    }

    UnifiedEncryptionResult encrypt(UnifiedEncryptRequest request) {
        Objects.requireNonNull(request, "request");
        context.guard().ensureOperational("unified-encrypt");
        EnvelopeService envelopeService = requireEnvelopeService();

        AlgorithmSelector.SelectionOutcome outcome;
        try {
            outcome = selector.select(request);
        } catch (RuntimeException e) {
            auditSelectionFailure(request, null, e);
            metricsFailure(null, "failure");
            throw e;
        }
        AlgorithmSelector.Selection selection = outcome.selection();
        if (selection == null) {
            RuntimeException failure = selectionFailure(outcome.report());
            auditSelectionFailure(request, outcome.report(), failure);
            metricsFailure(outcome.report(), "failure");
            throw failure;
        }

        Instant createdAt = context.clock().instant();
        byte[] headerHash = EnvelopeBinding.headerHash(2, selection.algorithm(),
                selection.keyId(), createdAt, Salt.empty(), null, request.attributes());
        AAD effectiveAad;
        try {
            effectiveAad = EnvelopeBinding.effectiveAad(request.aad(), headerHash);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                    "AAD is too large for a bound envelope");
        }

        EncryptRequest.Builder encryptBuilder = EncryptRequest.builder(selection.algorithm(),
                        selection.keyId(), request.plaintext(), request.caller())
                .aad(effectiveAad)
                .attributes(request.attributes());
        if (selection.requestedKeyVersion() != null) {
            encryptBuilder.keyVersion(selection.requestedKeyVersion());
        }

        EncryptedData data;
        Envelope envelope;
        boolean encryptionStarted = false;
        boolean encryptionFinished = false;
        try {
            encryptionStarted = true;
            data = crypto.encrypt(encryptBuilder.build(), createdAt);
            encryptionFinished = true;
            try {
                envelope = envelopeService.createBound(data, headerHash, request.attributes());
            } catch (EnvelopeException e) {
                if (e.errorCode() == ErrorCode.UNSUPPORTED_OPERATION) {
                    throw new ConfigurationException(ErrorCode.MISSING_DEPENDENCY,
                            "The installed envelope service cannot create bound envelopes");
                }
                throw e;
            }
            // EncryptedData carries the effective AAD used by the cipher. A v2
            // envelope stores the user AAD; decryptors reconstruct the effective
            // value from it and the authenticated header hash.
            envelope = envelope.toBuilder().aad(request.aad()).build();
            envelope = envelope.withEncoding(request.format(), request.encoding());
            envelopeService.validate(envelope);
        } catch (RuntimeException e) {
            if (!encryptionStarted) {
                auditSelectionFailure(request, outcome.report(), e);
                metricsFailure(outcome.report(), "failure");
            } else if (encryptionFinished) {
                auditEnvelopeFailure(request, selection.algorithm(), dataOrNull(e), e);
                metricsFailure(outcome.report(), "failure");
            }
            throw e;
        }

        SelectionReport report = outcome.report();
        auditSelected(request, selection, data, report);
        auditEnvelopeCreated(request, selection, data, envelope);
        metricsSuccess(report);
        return new UnifiedEncryptionResult(envelope, report);
    }

    byte[] decrypt(UnifiedDecryptRequest request) {
        Objects.requireNonNull(request, "request");
        context.guard().ensureOperational("unified-decrypt");
        EnvelopeService envelopeService = requireEnvelopeService();

        Envelope envelope;
        try {
            envelope = decode(request, envelopeService);
            if (request.formatHint() != null && envelope.format() != request.formatHint()) {
                throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                        "Envelope format does not match the expected format");
            }
            envelopeService.validate(envelope);
        } catch (EnvelopeException e) {
            auditParseFailure(request.caller(), e);
            throw e;
        }

        boolean legacy = envelope.version() == 1;
        AAD aad;
        try {
            if (envelope.version() == 2) {
                EnvelopeMetadataVerifier.verifyV2(envelope);
                aad = EnvelopeMetadataVerifier.effectiveAad(envelope);
                checkFreshness(envelope, request.maxAge());
            } else if (legacy) {
                if (!settings.allowLegacyV1(request.allowLegacyV1())) {
                    throw new EnvelopeException(ErrorCode.LEGACY_ENVELOPE_DENIED,
                            "Legacy v1 envelopes are not accepted");
                }
                if (request.maxAge() != null) {
                    throw new EnvelopeException(ErrorCode.LEGACY_ENVELOPE_DENIED,
                            "Freshness checks require a bound v2 envelope");
                }
                aad = envelope.aad();
            } else {
                throw new EnvelopeException(ErrorCode.UNSUPPORTED_ENVELOPE_VERSION,
                        "Unsupported envelope version");
            }
        } catch (EnvelopeException e) {
            if (e.errorCode() == ErrorCode.ENVELOPE_BINDING_MISMATCH) {
                auditBindingFailure(request.caller(), envelope, e);
            }
            throw e;
        }

        checkExpectedContext(request, envelope);
        auditParseSuccess(request.caller(), envelope);
        if (legacy) {
            auditLegacyAccepted(request.caller(), envelope);
        }

        DecryptRequest decryptRequest = DecryptRequest.builder(envelope.algorithm(),
                        envelope.keyId(), envelope.ciphertext(), request.caller())
                .keyVersion(envelope.keyVersion())
                .nonce(envelope.nonce())
                .tag(envelope.tag())
                .aad(aad)
                .build();
        try {
            return crypto.decrypt(decryptRequest);
        } catch (CryptoException e) {
            throw secureDecryptFailure(e);
        }
    }

    private Envelope decode(UnifiedDecryptRequest request, EnvelopeService envelopeService) {
        if (request.encodedEnvelope() != null) {
            return envelopeService.decode(request.encodedEnvelope());
        }
        String text = request.encodedText();
        if ((long) text.length() > 4L * settings.envelopeMaxBytes() + 16L) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_MALFORMED,
                    "Envelope text exceeds the maximum size");
        }
        BinaryEncoding encoding = request.encoding();
        if (encoding == null) {
            return envelopeService.decodeText(text);
        }
        try {
            byte[] bytes = switch (encoding) {
                case BASE64 -> Base64.getDecoder().decode(text);
                case BASE64URL -> Base64.getUrlDecoder().decode(text);
                case HEX -> hexDecode(text);
                case RAW -> throw new IllegalArgumentException("RAW is not a text encoding");
            };
            return envelopeService.decode(bytes);
        } catch (IllegalArgumentException e) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_MALFORMED,
                    "Envelope text is not valid for the requested encoding");
        }
    }

    private static byte[] hexDecode(String text) {
        if ((text.length() & 1) != 0) {
            throw new IllegalArgumentException("Odd hex length");
        }
        byte[] output = new byte[text.length() / 2];
        for (int index = 0; index < output.length; index++) {
            int high = Character.digit(text.charAt(index * 2), 16);
            int low = Character.digit(text.charAt(index * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("Invalid hex");
            }
            output[index] = (byte) ((high << 4) | low);
        }
        return output;
    }

    private void checkFreshness(Envelope envelope, Duration maxAge) {
        if (maxAge == null) {
            return;
        }
        Instant now = context.clock().instant();
        Instant created = envelope.createdAt();
        if (created.isAfter(now.plus(MAX_FUTURE_SKEW)) || created.isBefore(now.minus(maxAge))) {
            throw new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                    "Envelope is outside the accepted time window");
        }
    }

    private static void checkExpectedContext(UnifiedDecryptRequest request, Envelope envelope) {
        if (request.expectedAlgorithm() != null
                && !request.expectedAlgorithm().equals(envelope.algorithm())) {
            throw contextMismatch();
        }
        if (request.expectedKeyId() != null
                && !request.expectedKeyId().equals(envelope.keyId())) {
            throw contextMismatch();
        }
        if (request.expectedKeyVersion() != null
                && request.expectedKeyVersion() != envelope.keyVersion().value()) {
            throw contextMismatch();
        }
        if (request.expectedAad() != null && !request.expectedAad().equals(envelope.aad())) {
            throw contextMismatch();
        }
        for (Map.Entry<String, String> entry : request.expectedAttributes().entrySet()) {
            if (!entry.getValue().equals(envelope.attributes().get(entry.getKey()))) {
                throw contextMismatch();
            }
        }
    }

    private static EnvelopeException contextMismatch() {
        return new EnvelopeException(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                "Envelope does not match the expected context");
    }

    /**
     * Maps a single unambiguous rejection to the stable error family callers
     * already handle. Mixed candidate failures remain a generic selection error.
     */
    private static RuntimeException selectionFailure(SelectionReport report) {
        if (report != null && !report.candidates().isEmpty()) {
            var first = report.candidates().get(0).outcome();
            boolean uniform = report.candidates().stream()
                    .allMatch(decision -> decision.outcome() == first);
            if (uniform) {
                return switch (first) {
                    case ALGORITHM_PROHIBITED -> new PolicyException(
                            ErrorCode.ALGORITHM_PROHIBITED, "Algorithm is prohibited");
                    case ALGORITHM_EXPERIMENTAL -> new PolicyException(
                            ErrorCode.ALGORITHM_EXPERIMENTAL, "Algorithm is experimental");
                    case COMPLIANCE_MODE -> new PolicyException(
                            ErrorCode.COMPLIANCE_MODE_DENIED,
                            "Algorithm is not allowed by the compliance mode");
                    case POLICY_HINT_DENIED -> new PolicyException(
                            ErrorCode.POLICY_DENIED, "Algorithm is denied by policy");
                    case KEY_ALGORITHM_MISMATCH -> new KeyException(
                            ErrorCode.KEY_ALGORITHM_MISMATCH,
                            "Key algorithm does not match the requested algorithm");
                    case KEY_TYPE_MISMATCH -> new KeyException(
                            ErrorCode.KEY_USAGE_VIOLATION, "Key type is not compatible");
                    case KEY_SIZE -> new PolicyException(
                            ErrorCode.MIN_KEY_BITS_VIOLATION, "Key size is below the minimum");
                    case KEY_NOT_ACTIVE -> new KeyException(
                            ErrorCode.KEY_NOT_ACTIVE, "Key is not active for encryption");
                    case KEY_USAGE -> new KeyException(
                            ErrorCode.KEY_USAGE_VIOLATION, "Key usage does not permit encryption");
                    case KEY_TENANT -> new PolicyException(
                            ErrorCode.TENANT_VIOLATION, "Cross-tenant key access is denied");
                    case PROVIDER_UNAVAILABLE -> new CryptoException(
                            ErrorCode.ALGORITHM_UNSUPPORTED,
                            "Algorithm is not supported by any healthy provider");
                    case ALGORITHM_UNKNOWN -> new CryptoException(
                            ErrorCode.ALGORITHM_UNKNOWN, "Algorithm is not registered");
                    default -> new CryptoException(ErrorCode.ALGORITHM_SELECTION_FAILED,
                            "No eligible algorithm/key combination");
                };
            }
        }
        return new CryptoException(ErrorCode.ALGORITHM_SELECTION_FAILED,
                "No eligible algorithm/key combination");
    }

    private static CryptoException secureDecryptFailure(CryptoException failure) {
        ErrorCode code = failure.errorCode();
        if (code == ErrorCode.AUTHENTICATION_FAILED || code == ErrorCode.TAG_INVALID
                || code == ErrorCode.INVALID_CIPHERTEXT || code == ErrorCode.DECRYPTION_FAILED) {
            return new CryptoException(ErrorCode.AUTHENTICATION_FAILED,
                    "Cryptographic authentication failed");
        }
        return failure;
    }

    private EnvelopeService requireEnvelopeService() {
        EnvelopeService service = context.envelopeService();
        if (service == null) {
            throw new ConfigurationException(ErrorCode.MISSING_DEPENDENCY,
                    "No EnvelopeService is installed");
        }
        return service;
    }

    private void auditSelected(UnifiedEncryptRequest request,
                               AlgorithmSelector.Selection selection,
                               EncryptedData data, SelectionReport report) {
        appendAudit(AuditEvent.builder(AuditEventType.ALGORITHM_SELECTED,
                                AuditSeverity.INFO, AuditOutcome.SUCCESS)
                        .caller(request.caller())
                        .algorithm(selection.algorithm())
                        .keyId(selection.keyId())
                        .keyVersion(data.keyVersion())
                        .operation(Operation.ENCRYPT)
                        .message("Algorithm selected")
                        .detail("profile", report.profileId())
                        .detail("explicit", Boolean.toString(report.explicit()))
                        .detail("candidateCount", Integer.toString(report.candidates().size()))
                        .build(),
                context.auditFailureFailsOperation());
    }

    private void auditEnvelopeCreated(UnifiedEncryptRequest request,
                                      AlgorithmSelector.Selection selection,
                                      EncryptedData data, Envelope envelope) {
        appendAudit(AuditEvent.builder(AuditEventType.ENVELOPE_CREATED,
                                AuditSeverity.INFO, AuditOutcome.SUCCESS)
                        .caller(request.caller())
                        .algorithm(selection.algorithm())
                        .keyId(selection.keyId())
                        .keyVersion(data.keyVersion())
                        .operation(Operation.ENCRYPT)
                        .message("Envelope created")
                        .detail("version", Integer.toString(envelope.version()))
                        .detail("format", envelope.format().name())
                        .detail("encoding", envelope.binaryEncoding().name())
                        .build(),
                context.auditFailureFailsOperation());
    }

    private void auditSelectionFailure(UnifiedEncryptRequest request, SelectionReport report,
                                       RuntimeException failure) {
        AuditEvent.Builder builder = AuditEvent.builder(AuditEventType.ALGORITHM_SELECTION_FAILED,
                        AuditSeverity.WARN, AuditOutcome.DENIED)
                .caller(request.caller())
                .operation(Operation.ENCRYPT)
                .message("Algorithm selection failed")
                .detail("reason", errorCode(failure));
        if (report != null) {
            builder.detail("profile", report.profileId())
                    .detail("explicit", Boolean.toString(report.explicit()))
                    .detail("candidateCount", Integer.toString(report.candidates().size()));
        }
        appendAudit(builder.build(), false);
    }

    private void auditEnvelopeFailure(UnifiedEncryptRequest request, AlgorithmId algorithm,
                                      EncryptedData data, RuntimeException failure) {
        AuditEvent.Builder builder = AuditEvent.builder(AuditEventType.ENVELOPE_CREATED,
                        AuditSeverity.ERROR, AuditOutcome.FAILURE)
                .caller(request.caller())
                .algorithm(algorithm)
                .keyId(request.keyId())
                .keyVersion(data == null ? null : data.keyVersion())
                .operation(Operation.ENCRYPT)
                .message("Envelope creation failed")
                .detail("errorCode", errorCode(failure));
        appendAudit(builder.build(), false);
    }

    private void auditParseSuccess(cn.tolim.spissatus4j.contract.policy.CallerContext caller,
                                   Envelope envelope) {
        appendAudit(AuditEvent.builder(AuditEventType.ENVELOPE_PARSED,
                                AuditSeverity.INFO, AuditOutcome.SUCCESS)
                        .caller(caller)
                        .algorithm(envelope.algorithm())
                        .keyId(envelope.keyId())
                        .keyVersion(envelope.keyVersion())
                        .operation(Operation.DECRYPT)
                        .message("Envelope parsed")
                        .detail("version", Integer.toString(envelope.version()))
                        .build(),
                false);
    }

    private void auditParseFailure(cn.tolim.spissatus4j.contract.policy.CallerContext caller,
                                   RuntimeException failure) {
        appendAudit(AuditEvent.builder(AuditEventType.ENVELOPE_PARSED,
                                AuditSeverity.WARN, AuditOutcome.FAILURE)
                        .caller(caller)
                        .operation(Operation.DECRYPT)
                        .message("Envelope parsing failed")
                        .detail("errorCode", errorCode(failure))
                        .build(),
                false);
    }

    private void auditBindingFailure(cn.tolim.spissatus4j.contract.policy.CallerContext caller,
                                     Envelope envelope, RuntimeException failure) {
        appendAudit(AuditEvent.builder(AuditEventType.ENVELOPE_BINDING_FAILED,
                                AuditSeverity.ERROR, AuditOutcome.FAILURE)
                        .caller(caller)
                        .algorithm(envelope.algorithm())
                        .keyId(envelope.keyId())
                        .keyVersion(envelope.keyVersion())
                        .operation(Operation.DECRYPT)
                        .message("Envelope metadata authentication failed")
                        .detail("errorCode", errorCode(failure))
                        .build(),
                false);
        metricsIncrement(MetricNames.ENVELOPE_BINDING_FAILURES,
                Map.of("algorithm", algorithmTag(envelope.algorithm())));
    }

    private void auditLegacyAccepted(cn.tolim.spissatus4j.contract.policy.CallerContext caller,
                                     Envelope envelope) {
        appendAudit(AuditEvent.builder(AuditEventType.ENVELOPE_LEGACY_ACCEPTED,
                                AuditSeverity.WARN, AuditOutcome.SUCCESS)
                        .caller(caller)
                        .algorithm(envelope.algorithm())
                        .keyId(envelope.keyId())
                        .keyVersion(envelope.keyVersion())
                        .operation(Operation.DECRYPT)
                        .message("Legacy v1 envelope accepted")
                        .build(),
                false);
    }

    private void appendAudit(AuditEvent event, boolean enforce) {
        boolean failed = false;
        try {
            context.auditTrail().append(event);
            if (context.auditTrail().health() != HealthStatus.UP) {
                failed = true;
            }
        } catch (RuntimeException e) {
            failed = true;
        }
        if (failed) {
            metricsIncrement(MetricNames.AUDIT_WRITE_FAILURES, Map.of());
            if (enforce && context.auditFailureFailsOperation()) {
                throw new AuditException(ErrorCode.AUDIT_FAILURE, "Audit trail write failed");
            }
        }
    }

    private void metricsSuccess(SelectionReport report) {
        metricsIncrement(MetricNames.ALGORITHM_SELECTIONS, Map.of(
                "profile", profileTag(report),
                "algorithm", algorithmTag(report == null ? null : report.selectedAlgorithm()),
                "outcome", "success"));
    }

    private void metricsFailure(SelectionReport report, String outcome) {
        metricsIncrement(MetricNames.ALGORITHM_SELECTIONS, Map.of(
                "profile", profileTag(report),
                "algorithm", algorithmTag(report == null ? null : report.selectedAlgorithm()),
                "outcome", outcome));
        if (report != null) {
            for (var decision : report.candidates()) {
                if (!decision.selected()) {
                    metricsIncrement(MetricNames.ALGORITHM_SELECTION_FAILURES,
                            Map.of("reason", decision.outcome().name()));
                    break;
                }
            }
        }
    }

    private void metricsIncrement(String name, Map<String, String> tags) {
        try {
            context.metricsRecorder().increment(name, tags);
        } catch (RuntimeException ignored) {
            // instrumentation never fails an operation
        }
    }

    private static String profileTag(SelectionReport report) {
        if (report == null) {
            return "unknown";
        }
        return switch (report.profileId()) {
            case "EXPLICIT", "PREFERENCE" -> report.profileId();
            default -> {
                try {
                    yield SelectionProfile.valueOf(report.profileId()).name();
                } catch (IllegalArgumentException e) {
                    yield "unknown";
                }
            }
        };
    }

    private static String algorithmTag(AlgorithmId algorithm) {
        if (algorithm == null) {
            return "none";
        }
        return algorithm.isKnown() ? algorithm.id() : "unknown";
    }

    private static String errorCode(RuntimeException failure) {
        return failure instanceof SpissatusException se
                ? se.errorCode().name() : "INTERNAL_ERROR";
    }

    private static EncryptedData dataOrNull(RuntimeException failure) {
        return null;
    }
}