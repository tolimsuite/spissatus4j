package cn.tolim.spissatus4j.core.policy;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmCatalog;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmInfo;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.algorithm.SecurityStatus;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;
import cn.tolim.spissatus4j.contract.policy.SelectionHints;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Self-contained fallback policy used when the policy module is absent.
 *
 * <p>It enforces the catalog security posture, minimum key sizes, key usage
 * and state isolation, tenant isolation, anonymous-caller rejection and the
 * compliance mode. It is intentionally static; richer access rules, rate
 * limits and external policy providers are the policy module's job.</p>
 */
public final class StrictPolicyEngine implements PolicyEngine {

    private final ComplianceMode complianceMode;
    private final Clock clock;

    public StrictPolicyEngine() {
        this(ComplianceMode.STANDARD, Clock.systemUTC());
    }

    public StrictPolicyEngine(ComplianceMode complianceMode) {
        this(complianceMode, Clock.systemUTC());
    }

    public StrictPolicyEngine(ComplianceMode complianceMode, Clock clock) {
        this.complianceMode = Objects.requireNonNull(complianceMode, "complianceMode");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public String engineId() {
        return "core-strict-fallback";
    }

    @Override
    public PolicyDecision evaluate(PolicyRequest request) {
        Objects.requireNonNull(request, "request");
        try {
            PolicyDecision decision = PolicyDecision.allow("core-strict");
            decision = PolicyDecision.strictest(decision, algorithm(request));
            decision = PolicyDecision.strictest(decision, usage(request));
            decision = PolicyDecision.strictest(decision, access(request));
            decision = PolicyDecision.strictest(decision, tenant(request));
            return decision;
        } catch (RuntimeException e) {
            return PolicyDecision.deny(ReasonCodes.POLICY_UNAVAILABLE,
                    "Policy evaluation unavailable", "core-strict");
        }
    }

    private PolicyDecision algorithm(PolicyRequest request) {
        if (isLifecycleManagement(request.operation())) {
            return PolicyDecision.allow("core-strict.management");
        }
        AlgorithmId algorithm = request.algorithm();
        if (algorithm == null) {
            return null;
        }
        AlgorithmInfo info = algorithm.info();
        if (!algorithm.isKnown() || info.status() == SecurityStatus.UNKNOWN) {
            return PolicyDecision.deny(ReasonCodes.ALGORITHM_UNKNOWN,
                    "Algorithm is not registered", "core-strict.algorithm");
        }
        if (!complianceMode.allows(info)) {
            return PolicyDecision.deny(ReasonCodes.COMPLIANCE_MODE_VIOLATION,
                    complianceMode.violationReason(info), "core-strict.compliance");
        }
        if (info.status() == SecurityStatus.PROHIBITED) {
            return PolicyDecision.deny(ReasonCodes.ALGORITHM_PROHIBITED,
                    "Algorithm is prohibited", "core-strict.algorithm");
        }
        if (info.status() == SecurityStatus.EXPERIMENTAL) {
            return PolicyDecision.deny(ReasonCodes.ALGORITHM_EXPERIMENTAL,
                    "Experimental algorithms require an explicit policy", "core-strict.algorithm");
        }
        KeyDescriptor key = request.key();
        if (key != null && info.minKeyBits() > 0 && key.keyBits() > 0
                && key.keyBits() < info.minKeyBits()) {
            return PolicyDecision.deny(ReasonCodes.MIN_KEY_BITS,
                    "Key is below the algorithm minimum size", "core-strict.algorithm");
        }
        if (info.status() == SecurityStatus.DEPRECATED) {
            return PolicyDecision.warn(ReasonCodes.ALGORITHM_DEPRECATED,
                    "Deprecated algorithm use", "core-strict.algorithm");
        }
        return PolicyDecision.allow("core-strict.algorithm");
    }

    private PolicyDecision usage(PolicyRequest request) {
        KeyDescriptor key = request.key();
        if (key == null) {
            return null;
        }
        KeyUsage required = requiredUsage(request.operation());
        if (required != null && !key.supportsUsage(required)) {
            return PolicyDecision.deny(ReasonCodes.KEY_USAGE_MISMATCH,
                    "Key usage does not permit this operation", "core-strict.usage");
        }
        if (protecting(request.operation())) {
            if (!key.state().canProtect()) {
                return PolicyDecision.deny(ReasonCodes.KEY_NOT_ACTIVE,
                        "Key is not active for protection", "core-strict.usage");
            }
        } else if (required != null && !key.state().canProcessHistoricalData()) {
            return PolicyDecision.deny(ReasonCodes.KEY_NOT_ACTIVE,
                    "Key state does not permit this operation", "core-strict.usage");
        }
        if (key.expired(clock.instant())) {
            return PolicyDecision.deny(ReasonCodes.KEY_EXPIRED,
                    "Key has expired", "core-strict.usage");
        }
        return PolicyDecision.allow("core-strict.usage");
    }

    private static boolean isLifecycleManagement(Operation operation) {
        return operation == Operation.DESTROY_KEY || operation == Operation.REVOKE_KEY
                || operation == Operation.COMPROMISE_KEY || operation == Operation.DEACTIVATE_KEY
                || operation == Operation.READ_KEY;
    }

    private boolean protecting(Operation operation) {
        return switch (operation) {
            case ENCRYPT, SIGN, MAC, WRAP, DERIVE_KEY, STREAM_ENCRYPT -> true;
            default -> false;
        };
    }

    private PolicyDecision access(PolicyRequest request) {
        if (request.caller().isAnonymous()) {
            return PolicyDecision.deny(ReasonCodes.ANONYMOUS_CALLER,
                    "Anonymous callers are denied", "core-strict.access");
        }
        return PolicyDecision.allow("core-strict.access");
    }

    private PolicyDecision tenant(PolicyRequest request) {
        KeyDescriptor key = request.key();
        if (key == null) {
            return null;
        }
        String tenant = request.caller().tenantId();
        if (!key.tenantId().equals(tenant)
                && !request.caller().hasRole("crypto-cross-tenant")
                && !request.caller().hasRole("crypto-admin")) {
            return PolicyDecision.deny(ReasonCodes.TENANT_MISMATCH,
                    "Cross-tenant key access is denied", "core-strict.tenant");
        }
        return PolicyDecision.allow("core-strict.tenant");
    }

    private static KeyUsage requiredUsage(Operation operation) {
        return switch (operation) {
            case ENCRYPT, STREAM_ENCRYPT -> KeyUsage.ENCRYPT;
            case DECRYPT, STREAM_DECRYPT -> KeyUsage.DECRYPT;
            case SIGN -> KeyUsage.SIGN;
            case VERIFY -> KeyUsage.VERIFY;
            case MAC, VERIFY_MAC -> KeyUsage.MAC;
            case WRAP -> KeyUsage.WRAP;
            case UNWRAP -> KeyUsage.UNWRAP;
            case DERIVE_KEY -> KeyUsage.DERIVE;
            default -> null;
        };
    }

    @Override
    public SelectionHints selectionHints(CallerContext caller) {
        Map<AlgorithmId, Integer> minimums = new LinkedHashMap<>();
        for (AlgorithmInfo info : AlgorithmCatalog.all()) {
            if (info.minKeyBits() > 0) {
                minimums.put(info.id(), info.minKeyBits());
            }
        }
        return new SelectionHints("core-strict.selection", true, Set.of(), false, Set.of(),
                Map.copyOf(minimums), false);
    }

    @Override
    public HealthStatus health() {
        return HealthStatus.UP;
    }

    @Override
    public String toString() {
        return "StrictPolicyEngine[mode=" + complianceMode + "]";
    }

    /** Exposes the immutable rule list for diagnostics. */
    public List<String> ruleIds() {
        return List.of("core-strict.algorithm", "core-strict.usage", "core-strict.access",
                "core-strict.tenant");
    }
}