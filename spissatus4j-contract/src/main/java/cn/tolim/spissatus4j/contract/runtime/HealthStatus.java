package cn.tolim.spissatus4j.contract.runtime;

/** Health of a provider, runtime component or the whole facade. */
public enum HealthStatus {
    UP,
    DEGRADED,
    DOWN;

    public boolean isUsable() {
        return this != DOWN;
    }
}