package cn.tolim.spissatus4j.core.facade;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmFamily;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmInfo;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.algorithm.SecurityStatus;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.exception.PolicyException;
import cn.tolim.spissatus4j.contract.exception.SpissatusException;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeySelectionCandidate;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyUseOptions;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.SelectionHints;
import cn.tolim.spissatus4j.contract.unified.AlgorithmSuite;
import cn.tolim.spissatus4j.contract.unified.CandidateDecision;
import cn.tolim.spissatus4j.contract.unified.SelectionProfile;
import cn.tolim.spissatus4j.contract.unified.SelectionRejection;
import cn.tolim.spissatus4j.contract.unified.SelectionReport;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Deterministic algorithm/key selector for the unified entry point.
 *
 * <p>It performs hard capability filtering only. It never calls
 * {@link cn.tolim.spissatus4j.contract.policy.PolicyEngine#evaluate}; the
 * single authoritative policy decision is made later by the crypto service.</p>
 */
final class AlgorithmSelector {

    private static final int MAX_DECISIONS = 256;

    record Selection(AlgorithmId algorithm, KeyId keyId, Long requestedKeyVersion) {
    }

    record SelectionOutcome(Selection selection, SelectionReport report) {
    }

    private record KeyCandidate(KeyId keyId, KeySelectionCandidate key, Long requestedVersion,
                                SelectionRejection rejection) {
    }

    private final FacadeContext context;
    private final SelectionSettings settings;
    private final ProviderCapabilityIndex providers;

    AlgorithmSelector(FacadeContext context, SelectionSettings settings,
                      ProviderCapabilityIndex providers) {
        this.context = Objects.requireNonNull(context, "context");
        this.settings = Objects.requireNonNull(settings, "settings");
        this.providers = Objects.requireNonNull(providers, "providers");
    }

    SelectionOutcome select(UnifiedEncryptRequest request) {
        Objects.requireNonNull(request, "request");
        if (request.autoKeySelection() && !settings.allowAutoKeySelection()) {
            throw new PolicyException(ErrorCode.POLICY_DENIED,
                    "Automatic key selection is not enabled");
        }
        if (request.candidateKeyIds().size() > settings.maxCandidates()) {
            throw new cn.tolim.spissatus4j.contract.exception.ConfigurationException(
                    ErrorCode.INVALID_PARAMETER, "Too many candidate keys");
        }
        if (request.candidates().size() > settings.maxCandidates()) {
            throw new cn.tolim.spissatus4j.contract.exception.ConfigurationException(
                    ErrorCode.INVALID_PARAMETER, "Too many candidate algorithms");
        }
        SelectionProfile profile = settings.profileFor(request);
        boolean explicit = request.algorithm() != null || request.suite() != null;
        boolean elevated = explicit || !request.candidates().isEmpty();
        String profileId = profileId(request, profile);
        List<AlgorithmId> algorithms = algorithms(request, profile);
        List<KeyCandidate> keys = keys(request);

        List<CandidateDecision> decisions = new ArrayList<>();
        SelectionHints hints = hints(request.caller());
        for (AlgorithmId algorithm : algorithms) {
            AlgorithmInfo info = algorithm.info();
            SelectionRejection algorithmRejection = algorithmRejection(
                    algorithm, info, request, profile, elevated, hints);
            if (algorithmRejection != null) {
                for (KeyCandidate key : keys) {
                    add(decisions, key.keyId(), algorithm, false, algorithmRejection);
                }
                continue;
            }
            for (KeyCandidate key : keys) {
                if (key.rejection() != null) {
                    add(decisions, key.keyId(), algorithm, false, key.rejection());
                    continue;
                }
                SelectionRejection keyRejection = keyRejection(
                        key.key(), algorithm, info, request, hints);
                if (keyRejection != null) {
                    add(decisions, key.keyId(), algorithm, false, keyRejection);
                    continue;
                }
                add(decisions, key.keyId(), algorithm, true, SelectionRejection.SELECTED);
                Selection selection = new Selection(algorithm, key.keyId(),
                        key.requestedVersion());
                return new SelectionOutcome(selection, new SelectionReport(profileId, explicit,
                        key.keyId(), algorithm, decisions));
            }
        }
        return new SelectionOutcome(null, new SelectionReport(profileId, explicit,
                null, null, decisions));
    }

    private List<AlgorithmId> algorithms(UnifiedEncryptRequest request,
                                         SelectionProfile profile) {
        if (request.algorithm() != null) {
            return List.of(request.algorithm());
        }
        if (request.suite() != null) {
            return List.of(request.suite().algorithm());
        }
        if (!request.candidates().isEmpty()) {
            return request.candidates();
        }
        return settings.preferredOrder(profile);
    }

    private String profileId(UnifiedEncryptRequest request, SelectionProfile profile) {
        if (request.algorithm() != null) {
            return "EXPLICIT";
        }
        if (request.suite() != null) {
            return request.suite().id();
        }
        if (!request.candidates().isEmpty()) {
            return "PREFERENCE";
        }
        return profile.name();
    }

    private List<KeyCandidate> keys(UnifiedEncryptRequest request) {
        CallerContext caller = request.caller();
        KeyUseOptions useOptions = KeyUseOptions.forEncryption(
                settings.allowDeactivatedEncryption(request));
        if (request.autoKeySelection()) {
            return autoKeys(caller);
        }
        if (request.keyId() != null) {
            KeyDescriptor descriptor = peek(request.keyId(), request.keyVersion(), caller,
                    useOptions);
            return List.of(new KeyCandidate(request.keyId(),
                    KeySelectionCandidate.from(descriptor), request.keyVersion(), null));
        }
        List<KeyCandidate> candidates = new ArrayList<>();
        for (KeyId keyId : request.candidateKeyIds()) {
            try {
                KeyDescriptor descriptor = peek(keyId, request.keyVersion(), caller, useOptions);
                candidates.add(new KeyCandidate(keyId, KeySelectionCandidate.from(descriptor),
                        request.keyVersion(), null));
            } catch (PolicyException e) {
                throw e;
            } catch (KeyException e) {
                if (e.errorCode() == ErrorCode.KEY_PROVIDER_FAILURE) {
                    throw e;
                }
                candidates.add(new KeyCandidate(keyId, null, request.keyVersion(),
                        keyRejection(e.errorCode())));
            } catch (RuntimeException e) {
                throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                        "Key resolution failed", e);
            }
        }
        return candidates;
    }

    /**
     * Advisory, non-policy key enumeration for the caller's own tenant. The
     * final authoritative policy decision still runs on the selected key.
     */
    private List<KeyCandidate> autoKeys(CallerContext caller) {
        List<KeySelectionCandidate> discovered;
        try {
            discovered = context.keyManager().candidateKeys(KeyUsage.ENCRYPT, caller,
                    settings.maxCandidates());
        } catch (PolicyException e) {
            throw e;
        } catch (SpissatusException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                    "Key enumeration failed", e);
        }
        List<KeyCandidate> candidates = new ArrayList<>();
        if (discovered == null) {
            return candidates;
        }
        java.util.LinkedHashMap<KeyId, KeySelectionCandidate> unique =
                new java.util.LinkedHashMap<>();
        for (KeySelectionCandidate candidate : discovered) {
            if (candidate == null || !caller.tenantId().equals(candidate.tenantId())) {
                continue;
            }
            unique.putIfAbsent(candidate.keyId(), candidate);
            if (unique.size() >= settings.maxCandidates()) {
                break;
            }
        }
        for (KeySelectionCandidate candidate : unique.values()) {
            candidates.add(new KeyCandidate(candidate.keyId(), candidate, null, null));
        }
        return candidates;
    }

    private KeyDescriptor peek(KeyId keyId, Long keyVersion, CallerContext caller,
                               KeyUseOptions useOptions) {
        try {
            return context.keyManager().peekForUse(keyId, keyVersion, KeyUsage.ENCRYPT,
                    caller, useOptions);
        } catch (SpissatusException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, "Key resolution failed", e);
        }
    }

    private SelectionHints hints(CallerContext caller) {
        try {
            SelectionHints hints = context.policyEngine().selectionHints(caller);
            return hints == null ? SelectionHints.none() : hints;
        } catch (RuntimeException e) {
            // Hints are non-authoritative; the final policy decision fails closed.
            return SelectionHints.none();
        }
    }

    private SelectionRejection algorithmRejection(AlgorithmId algorithm, AlgorithmInfo info,
                                                  UnifiedEncryptRequest request,
                                                  SelectionProfile profile, boolean elevated,
                                                  SelectionHints hints) {
        if (!algorithm.isKnown() || info.family() == AlgorithmFamily.UNKNOWN) {
            return SelectionRejection.ALGORITHM_UNKNOWN;
        }
        if (info.status() == SecurityStatus.UNKNOWN) {
            return SelectionRejection.ALGORITHM_UNKNOWN;
        }
        if (info.status() == SecurityStatus.PROHIBITED) {
            return SelectionRejection.ALGORITHM_PROHIBITED;
        }
        if (info.status() == SecurityStatus.EXPERIMENTAL) {
            if (!elevated || !settings.allowExperimental(request)
                    || (hints.available() && !hints.allowExperimental())) {
                return SelectionRejection.ALGORITHM_EXPERIMENTAL;
            }
        }
        if (info.status() == SecurityStatus.DEPRECATED
                && (!elevated || !settings.allowDeprecated(request))) {
            return SelectionRejection.ALGORITHM_DEPRECATED;
        }
        if (!context.complianceMode().allows(info)) {
            return SelectionRejection.COMPLIANCE_MODE;
        }
        if (!familyAllowed(info, profile)) {
            return SelectionRejection.NOT_IN_PROFILE;
        }
        if (info.family() == AlgorithmFamily.AEAD
                && (info.nonceBytes() <= 0 || info.tagBytes() <= 0)) {
            return SelectionRejection.NOT_IN_PROFILE;
        }
        if (info.family() == AlgorithmFamily.SYMMETRIC && info.tagBytes() <= 0) {
            return SelectionRejection.NOT_IN_PROFILE;
        }
        if (info.family() == AlgorithmFamily.ASYMMETRIC && !request.aad().isEmpty()) {
            return SelectionRejection.AAD_UNSUPPORTED;
        }
        if (hints.available() && !hints.permits(algorithm)) {
            return SelectionRejection.POLICY_HINT_DENIED;
        }
        if (!providers.hasAvailableProvider(algorithm)) {
            return SelectionRejection.PROVIDER_UNAVAILABLE;
        }
        return null;
    }

    private static boolean familyAllowed(AlgorithmInfo info, SelectionProfile profile) {
        AlgorithmFamily family = info.family();
        if (profile == null) {
            // Explicit selection may use AEAD, EtM-capable block modes or an
            // asymmetric cipher. Asymmetric v2 envelopes bind metadata by
            // prefixing the ciphertext plaintext instead of AAD.
            if (family == AlgorithmFamily.AEAD || family == AlgorithmFamily.ASYMMETRIC) {
                return true;
            }
            return family == AlgorithmFamily.SYMMETRIC && viableEtm(info);
        }
        return switch (profile) {
            case AUTO_AEAD, FIPS_AEAD, GM_AEAD, GM_HYBRID_AEAD ->
                    family == AlgorithmFamily.AEAD;
            case AUTO_AEAD_THEN_ETM -> family == AlgorithmFamily.AEAD
                    || (family == AlgorithmFamily.SYMMETRIC && viableEtm(info));
        };
    }

    private static boolean viableEtm(AlgorithmInfo info) {
        AlgorithmId id = info.id();
        return info.tagBytes() > 0
                && !id.equals(AlgorithmId.AES_ECB)
                && !id.equals(AlgorithmId.SM4_ECB)
                && !id.equals(AlgorithmId.AES_KW)
                && !id.equals(AlgorithmId.SM4);
    }

    private SelectionRejection keyRejection(KeySelectionCandidate key, AlgorithmId algorithm,
                                            AlgorithmInfo info, UnifiedEncryptRequest request,
                                            SelectionHints hints) {
        Objects.requireNonNull(key, "key");
        boolean deactivatedAllowed = settings.allowDeactivatedEncryption(request);
        if (key.state() != KeyState.ACTIVE
                && !(deactivatedAllowed && key.state() == KeyState.DEACTIVATED)) {
            return SelectionRejection.KEY_NOT_ACTIVE;
        }
        if (!key.supportsUsage(KeyUsage.ENCRYPT)) {
            return SelectionRejection.KEY_USAGE;
        }
        if (key.expired(context.clock().instant())) {
            return SelectionRejection.KEY_EXPIRED;
        }
        if (!key.algorithm().isKnown()
                || key.algorithm().info().status() == SecurityStatus.PROHIBITED
                || key.algorithm().info().status() == SecurityStatus.UNKNOWN) {
            // Do not let a key created for a prohibited algorithm be laundered
            // into an allowed mode through family reuse.
            return SelectionRejection.KEY_ALGORITHM_MISMATCH;
        }
        // Tenant access is enforced by peekForUse and the authoritative policy;
        // a caller holding a configured cross-tenant role must remain usable.
        if (!algorithmMatches(key, algorithm, request)) {
            return SelectionRejection.KEY_ALGORITHM_MISMATCH;
        }
        if (!keyTypeCompatible(key.type(), algorithm)) {
            return SelectionRejection.KEY_TYPE_MISMATCH;
        }
        int required = info.minKeyBits();
        if (hints.available()) {
            required = Math.max(required, hints.minimumKeyBits(algorithm));
        }
        AlgorithmSuite suite = request.suite();
        if (suite != null) {
            if (!suite.keyTypes().contains(key.type())) {
                return SelectionRejection.KEY_TYPE_MISMATCH;
            }
            required = Math.max(required, suite.minKeyBits());
        }
        if (required > 0 && (key.keyBits() == 0 || key.keyBits() < required)) {
            return SelectionRejection.KEY_SIZE;
        }
        return null;
    }

    private boolean algorithmMatches(KeySelectionCandidate key, AlgorithmId algorithm,
                                     UnifiedEncryptRequest request) {
        if (key.algorithm().equals(algorithm)) {
            return true;
        }
        if (!settings.allowFamilyReuse(request)) {
            return false;
        }
        if (!isSymmetricKeyType(key.type())) {
            return false;
        }
        return sameSymmetricPrimitive(key.algorithm(), algorithm);
    }

    private static boolean sameSymmetricPrimitive(AlgorithmId left, AlgorithmId right) {
        return (isAes(left) && isAes(right)) || (isSm4(left) && isSm4(right));
    }

    private static boolean keyTypeCompatible(KeyType type, AlgorithmId algorithm) {
        return switch (algorithm.family()) {
            case AEAD, SYMMETRIC -> switch (type) {
                case AES -> isAes(algorithm);
                case SM4 -> isSm4(algorithm);
                case SYMMETRIC, RAW -> isAes(algorithm) || isSm4(algorithm)
                        || algorithm.equals(AlgorithmId.CHACHA20_POLY1305);
                default -> false;
            };
            case ASYMMETRIC -> switch (algorithm.id()) {
                case "RSA-OAEP", "RSA-PKCS1-V1.5" -> type == KeyType.RSA;
                case "ECIES" -> type == KeyType.EC;
                case "SM2" -> type == KeyType.SM2;
                case "ML-KEM-768" -> type == KeyType.KEM || type == KeyType.RAW;
                default -> false;
            };
            default -> false;
        };
    }

    private static boolean isSymmetricKeyType(KeyType type) {
        return type == KeyType.AES || type == KeyType.SM4 || type == KeyType.SYMMETRIC
                || type == KeyType.RAW;
    }

    private static boolean isAes(AlgorithmId algorithm) {
        return algorithm.equals(AlgorithmId.AES_GCM) || algorithm.equals(AlgorithmId.AES_CBC)
                || algorithm.equals(AlgorithmId.AES_CTR) || algorithm.equals(AlgorithmId.AES_CFB)
                || algorithm.equals(AlgorithmId.AES_OFB) || algorithm.equals(AlgorithmId.AES_KW)
                || algorithm.equals(AlgorithmId.AES_ECB);
    }

    private static boolean isSm4(AlgorithmId algorithm) {
        return algorithm.equals(AlgorithmId.SM4) || algorithm.equals(AlgorithmId.SM4_GCM)
                || algorithm.equals(AlgorithmId.SM4_CBC) || algorithm.equals(AlgorithmId.SM4_CTR)
                || algorithm.equals(AlgorithmId.SM4_ECB);
    }

    private static SelectionRejection keyRejection(ErrorCode code) {
        return switch (code) {
            case KEY_NOT_ACTIVE, KEY_DESTROYED -> SelectionRejection.KEY_NOT_ACTIVE;
            case KEY_USAGE_VIOLATION -> SelectionRejection.KEY_USAGE;
            case TENANT_VIOLATION -> SelectionRejection.KEY_TENANT;
            case MIN_KEY_BITS_VIOLATION -> SelectionRejection.KEY_SIZE;
            default -> SelectionRejection.KEY_NOT_FOUND;
        };
    }

    private static void add(List<CandidateDecision> decisions, KeyId keyId,
                            AlgorithmId algorithm, boolean selected,
                            SelectionRejection outcome) {
        if (decisions.size() < MAX_DECISIONS) {
            decisions.add(new CandidateDecision(keyId, algorithm, selected, outcome));
        }
    }
}