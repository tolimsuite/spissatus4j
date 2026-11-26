package cn.tolim.spissatus4j.contract.key;

/**
 * Key lifecycle state.
 *
 * <p>Only {@link #ACTIVE} keys may encrypt, sign, wrap or MAC.
 * {@link #DEACTIVATED} keys may only decrypt, verify or unwrap historical
 * data. All other states are terminal for cryptographic use.</p>
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