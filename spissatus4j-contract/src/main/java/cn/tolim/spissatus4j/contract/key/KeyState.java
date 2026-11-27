package cn.tolim.spissatus4j.contract.key;

/**
 * Key lifecycle state.
 *
 * <p>Only {@link #ACTIVE} keys may normally encrypt, sign, wrap or MAC.
 * {@link #DEACTIVATED} keys may only process historical data (decrypt, verify,
 * unwrap) unless an operator setting and an explicit encryption request both
 * opt in through {@link KeyUseOptions} and the policy engine still allows it.
 * All other states are terminal for cryptographic use.</p>
 */
public enum KeyState {
    PRE_ACTIVATION,
    ACTIVE,
    DEACTIVATED,
    COMPROMISED,
    REVOKED,
    DESTROYED,
    DESTROYED_COMPROMISED;

    public boolean canProtect() {
        return this == ACTIVE;
    }

    public boolean canProcessHistoricalData() {
        return this == ACTIVE || this == DEACTIVATED;
    }

    public boolean terminal() {
        return this == DESTROYED || this == DESTROYED_COMPROMISED;
    }
}