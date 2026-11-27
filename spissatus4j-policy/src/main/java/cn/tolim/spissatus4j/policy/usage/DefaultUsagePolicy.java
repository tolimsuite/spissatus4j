package cn.tolim.spissatus4j.policy.usage;

import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;
import cn.tolim.spissatus4j.contract.policy.UsagePolicy;

import java.time.Clock;
import java.util.Objects;

/**
 * Default key-usage isolation policy.
 *
 * <p>The rule applies only when a {@link KeyDescriptor} is present. It maps the
 * requested {@link Operation} to the single {@link KeyUsage} the key must
 * carry, checks that the lifecycle state may protect new data (ENCRYPT, SIGN,
 * WRAP, MAC, DERIVE) or process historical data (DECRYPT, VERIFY, UNWRAP), and
 * rejects expired keys. ENCRYPT with a DEACTIVATED key is allowed only when
 * the request carries the operator-and-request opt-in flag; the key manager
 * enforces the same switch before material is read. Lifecycle operations that
 * do not consume a key usage are left to the key manager.</p>
 */
public final class DefaultUsagePolicy implements UsagePolicy {

    /** Stable, non-sensitive policy identifier. */
    public static final String RULE_ID = "usage";

    private final Clock clock;

    /** Creates a policy using the system UTC clock for expiry checks. */
    public DefaultUsagePolicy() {
        this(Clock.systemUTC());
    }

    /**
     * Creates a policy using the supplied clock for expiry checks.
     *
     * @param clock clock used to determine whether a key has expired
     */
    public DefaultUsagePolicy(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public PolicyDecision evaluate(PolicyRequest request) {
        if (request == null) {
            return PolicyDecision.deny(ReasonCodes.POLICY_UNAVAILABLE,
                    "No policy request available", RULE_ID);
        }
        KeyDescriptor key = request.key();
        if (key == null) {
            return PolicyDecision.allow(RULE_ID);
        }
        KeyUsage required = requiredUsage(request.operation());
        if (required == null) {
            return PolicyDecision.allow(RULE_ID);
        }
        if (!key.supportsUsage(required)) {
            return PolicyDecision.deny(ReasonCodes.KEY_USAGE_MISMATCH,
                    "Key usage does not permit this operation", RULE_ID);
        }
        boolean suitable;
        if (protecting(required)) {
            suitable = key.state().canProtect()
                    || (required == KeyUsage.ENCRYPT && request.allowDeactivatedEncryption()
                        && key.state() == KeyState.DEACTIVATED);
        } else {
            suitable = key.state().canProcessHistoricalData();
        }
        if (!suitable) {
            return PolicyDecision.deny(ReasonCodes.KEY_NOT_ACTIVE,
                    "Key state does not permit this operation", RULE_ID);
        }
        if (key.expired(clock.instant())) {
            return PolicyDecision.deny(ReasonCodes.KEY_EXPIRED,
                    "Key has expired", RULE_ID);
        }
        return PolicyDecision.allow(RULE_ID);
    }

    /**
     * Maps an operation to the key usage it requires, or {@code null} when the
     * operation does not consume a key usage.
     */
    static KeyUsage requiredUsage(Operation operation) {
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

    private static boolean protecting(KeyUsage usage) {
        return switch (usage) {
            case ENCRYPT, SIGN, WRAP, MAC, DERIVE -> true;
            case DECRYPT, VERIFY, UNWRAP -> false;
        };
    }

    /**
     * Reports whether a key state may serve the given usage. Exposed for
     * diagnostics and tests; the value is derived from {@link KeyState}.
     */
    public static boolean statePermits(KeyState state, KeyUsage usage) {
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(usage, "usage");
        return protecting(usage) ? state.canProtect() : state.canProcessHistoricalData();
    }
}