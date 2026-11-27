package cn.tolim.spissatus4j.contract.key;

/**
 * Per-operation key-state options for data use.
 *
 * <p>{@link #allowDeactivatedEncryption()} relaxes the default rule that only
 * {@link KeyState#ACTIVE} keys may protect new data. It is never enabled by
 * default: an operator setting and an explicit request flag must both allow it,
 * and the authoritative policy decision still applies. All other protecting
 * usages (sign, wrap, MAC, derive) remain ACTIVE-only.</p>
 */
public record KeyUseOptions(boolean allowDeactivatedEncryption) {

    /** Strict options: ACTIVE-only protection and historical use of DEACTIVATED keys. */
    public static final KeyUseOptions STRICT = new KeyUseOptions(false);

    public static KeyUseOptions strict() {
        return STRICT;
    }

    public static KeyUseOptions forEncryption(boolean allowDeactivatedEncryption) {
        return allowDeactivatedEncryption ? new KeyUseOptions(true) : STRICT;
    }
}