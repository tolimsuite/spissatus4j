package cn.tolim.spissatus4j.core.facade;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.api.Capabilities;
import cn.tolim.spissatus4j.contract.api.CryptoService;
import cn.tolim.spissatus4j.contract.api.Spissatus;
import cn.tolim.spissatus4j.contract.audit.AuditEvent;
import cn.tolim.spissatus4j.contract.audit.AuditEventType;
import cn.tolim.spissatus4j.contract.audit.AuditOutcome;
import cn.tolim.spissatus4j.contract.audit.AuditSeverity;
import cn.tolim.spissatus4j.contract.audit.AuditTrail;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.DecryptRequest;
import cn.tolim.spissatus4j.contract.crypto.EncryptRequest;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyManager;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.RuntimeState;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import cn.tolim.spissatus4j.contract.unified.UnifiedDecryptRequest;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptRequest;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptionResult;
import cn.tolim.spissatus4j.core.runtime.DefaultFailClosedGuard;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/** Default facade implementation. Thread-safe after construction. */
public final class DefaultSpissatus implements Spissatus {

    private static final System.Logger LOG = System.getLogger(DefaultSpissatus.class.getName());

    private final FacadeContext context;
    private final DefaultFailClosedGuard guard;
    private final DefaultCryptoService crypto;
    private final DefaultUnifiedCryptoService unified;
    private final Capabilities capabilities;
    private final AtomicBoolean closed = new AtomicBoolean();

    public DefaultSpissatus(FacadeContext context, DefaultFailClosedGuard guard) {
        this.context = Objects.requireNonNull(context, "context");
        this.guard = Objects.requireNonNull(guard, "guard");
        this.crypto = new DefaultCryptoService(context);
        this.unified = new DefaultUnifiedCryptoService(context, crypto);
        this.capabilities = buildCapabilities();
    }

    private Capabilities buildCapabilities() {
        Set<AlgorithmId> supported = new LinkedHashSet<>();
        List<Capabilities.ProviderCapability> providers = new ArrayList<>();
        boolean fipsOnly = context.complianceMode()
                == cn.tolim.spissatus4j.contract.compliance.ComplianceMode.FIPS;
        for (AlgorithmProvider provider : context.providers()) {
            Set<AlgorithmId> algorithms;
            try {
                algorithms = Set.copyOf(provider.supportedAlgorithms());
            } catch (RuntimeException e) {
                algorithms = Set.of();
            }
            if (fipsOnly && !provider.fipsCapable()) {
                algorithms = Set.of();
            }
            supported.addAll(algorithms);
            providers.add(new Capabilities.ProviderCapability(provider.providerId(),
                    provider.priority(), algorithms,
                    context.providerHealth().getOrDefault(provider.providerId(), HealthStatus.UP)));
        }
        boolean fipsAvailable = context.complianceMode()
                == cn.tolim.spissatus4j.contract.compliance.ComplianceMode.FIPS
                || Boolean.parseBoolean(context.settings().getOrDefault("spissatus.fips.enabled", "false"));
        boolean gmAvailable = supported.contains(AlgorithmId.SM2)
                || supported.contains(AlgorithmId.SM3)
                || supported.contains(AlgorithmId.SM4_GCM)
                || supported.contains(AlgorithmId.SM4_CBC)
                || supported.contains(AlgorithmId.SM4_CTR);
        return new Capabilities("1.0.0", Set.copyOf(supported), List.copyOf(providers),
                context.complianceMode(), fipsAvailable, gmAvailable, health());
    }

    @Override
    public CryptoService crypto() {
        return crypto;
    }

    @Override
    public KeyManager keyManager() {
        return context.keyManager();
    }

    @Override
    public EnvelopeService envelopeService() {
        if (context.envelopeService() == null) {
            throw new ConfigurationException(ErrorCode.MISSING_DEPENDENCY,
                    "No EnvelopeService is installed");
        }
        return context.envelopeService();
    }

    @Override
    public StreamCipherService streamCipherService() {
        if (context.streamCipherService() == null) {
            throw new ConfigurationException(ErrorCode.MISSING_DEPENDENCY,
                    "No StreamCipherService is installed");
        }
        return context.streamCipherService();
    }

    @Override
    public PolicyEngine policyEngine() {
        return context.policyEngine();
    }

    @Override
    public AuditTrail auditTrail() {
        return context.auditTrail();
    }

    @Override
    public cn.tolim.spissatus4j.contract.audit.MetricsRecorder metricsRecorder() {
        return context.metricsRecorder();
    }

    @Override
    public Capabilities capabilities() {
        return capabilities;
    }

    @Override
    public SelfCheckReport selfCheckReport() {
        return context.selfCheckReport();
    }

    @Override
    public HealthStatus health() {
        HealthStatus stateHealth = switch (guard.state()) {
            case READY -> HealthStatus.UP;
            case DEGRADED -> HealthStatus.DEGRADED;
            case STARTING, UNAVAILABLE, CLOSED -> HealthStatus.DOWN;
        };
        if (stateHealth == HealthStatus.DOWN) {
            return HealthStatus.DOWN;
        }
        HealthStatus audit = safeHealth(context.auditTrail()::health);
        HealthStatus keys = safeHealth(context.keyManager()::health);
        HealthStatus policy = safeHealth(context.policyEngine()::health);
        HealthStatus random = safeHealth(context.randomService()::health);
        HealthStatus nonce = safeHealth(context.nonceReuseDetector()::health);
        for (HealthStatus component : new HealthStatus[]{audit, keys, policy, random, nonce}) {
            if (component == HealthStatus.DOWN) {
                return HealthStatus.DOWN;
            }
        }
        for (HealthStatus component : new HealthStatus[]{audit, keys, policy, random, nonce}) {
            if (component == HealthStatus.DEGRADED) {
                return HealthStatus.DEGRADED;
            }
        }
        return stateHealth;
    }

    private static HealthStatus safeHealth(java.util.function.Supplier<HealthStatus> supplier) {
        try {
            HealthStatus status = supplier.get();
            return status == null ? HealthStatus.DOWN : status;
        } catch (RuntimeException e) {
            return HealthStatus.DOWN;
        }
    }

    @Override
    public RuntimeState state() {
        return guard.state();
    }

    @Override
    public UnifiedEncryptionResult encrypt(UnifiedEncryptRequest request) {
        return unified.encrypt(request);
    }

    @Override
    public byte[] decrypt(UnifiedDecryptRequest request) {
        return unified.decrypt(request);
    }

    @Override
    public Envelope encryptToEnvelope(EncryptRequest request, EnvelopeFormat format,
                                      BinaryEncoding encoding) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(format, "format");
        Objects.requireNonNull(encoding, "encoding");
        guard.ensureOperational("encrypt-envelope");
        EnvelopeService envelopeService = envelopeService();
        try {
            var data = crypto.encrypt(request);
            Envelope envelope = envelopeService.create(data, request.attributes())
                    .withEncoding(format, encoding);
            envelopeService.validate(envelope);
            auditBestEffort(request.caller(), request.algorithm(), data.keyVersion(),
                    AuditEventType.ENVELOPE_CREATED, AuditOutcome.SUCCESS, "Envelope created");
            return envelope;
        } catch (RuntimeException e) {
            auditBestEffort(request.caller(), request.algorithm(), null,
                    AuditEventType.ENVELOPE_CREATED, AuditOutcome.FAILURE, "Envelope creation failed");
            throw e;
        }
    }

    @Override
    public byte[] decryptEnvelope(byte[] encodedEnvelope, CallerContext caller) {
        Objects.requireNonNull(encodedEnvelope, "encodedEnvelope");
        Objects.requireNonNull(caller, "caller");
        guard.ensureOperational("decrypt-envelope");
        EnvelopeService envelopeService = envelopeService();
        Envelope envelope;
        try {
            envelope = envelopeService.decode(encodedEnvelope);
            envelopeService.validate(envelope);
        } catch (RuntimeException e) {
            auditBestEffort(caller, null, null, AuditEventType.ENVELOPE_PARSED,
                    AuditOutcome.FAILURE, "Envelope parsing failed");
            throw e instanceof EnvelopeException ? e
                    : new EnvelopeException(ErrorCode.ENVELOPE_MALFORMED,
                    "Envelope could not be parsed", e);
        }
        auditBestEffort(caller, envelope.algorithm(), envelope.keyVersion(),
                AuditEventType.ENVELOPE_PARSED, AuditOutcome.SUCCESS, "Envelope parsed");
        AAD aad = envelope.aad();
        if (envelope.version() == 2) {
            try {
                EnvelopeMetadataVerifier.verifyV2(envelope);
                aad = EnvelopeMetadataVerifier.effectiveAad(envelope);
            } catch (RuntimeException e) {
                auditBestEffort(caller, envelope.algorithm(), envelope.keyVersion(),
                        AuditEventType.ENVELOPE_BINDING_FAILED, AuditOutcome.FAILURE,
                        "Envelope metadata authentication failed");
                throw e;
            }
        }
        DecryptRequest request = DecryptRequest.builder(envelope.algorithm(), envelope.keyId(),
                        envelope.ciphertext(), caller)
                .keyVersion(envelope.keyVersion())
                .nonce(envelope.nonce())
                .tag(envelope.tag())
                .aad(aad)
                .build();
        return crypto.decrypt(request);
    }

    private void auditBestEffort(CallerContext caller, AlgorithmId algorithm,
                                 cn.tolim.spissatus4j.contract.key.KeyVersion version,
                                 AuditEventType type, AuditOutcome outcome, String message) {
        try {
            context.auditTrail().append(AuditEvent.builder(type,
                            outcome == AuditOutcome.SUCCESS ? AuditSeverity.INFO : AuditSeverity.WARN,
                            outcome)
                    .caller(caller)
                    .algorithm(algorithm)
                    .keyVersion(version)
                    .message(message)
                    .build());
        } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.WARNING, "Envelope audit write failed");
        }
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        guard.close();
        for (SpissatusModule module : context.modules()) {
            try {
                module.close();
            } catch (RuntimeException e) {
                LOG.log(System.Logger.Level.WARNING, "Module close failed: {0}", module.moduleId());
            }
        }
        try {
            context.auditTrail().close();
        } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.WARNING, "Audit trail close failed");
        }
        closeQuietly(context.keyManager());
        for (AlgorithmProvider provider : context.providers()) {
            closeQuietly(provider);
        }
        closeIfAutoCloseable(context.envelopeService());
        closeIfAutoCloseable(context.streamCipherService());
        closeIfAutoCloseable(context.metricsRecorder());
        for (var alertSink : context.alertSinks()) {
            closeIfAutoCloseable(alertSink);
        }
    }

    private static void closeQuietly(AutoCloseable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (Exception e) {
            LOG.log(System.Logger.Level.WARNING, "spissatus4j component close failed");
        }
    }

    private static void closeIfAutoCloseable(Object candidate) {
        if (candidate instanceof AutoCloseable closeable) {
            closeQuietly(closeable);
        }
    }

    @Override
    public String toString() {
        return "DefaultSpissatus[state=" + guard.state() + ", providers="
                + context.providers().size() + "]";
    }
}