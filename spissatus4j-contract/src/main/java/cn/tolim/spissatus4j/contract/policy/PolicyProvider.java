package cn.tolim.spissatus4j.contract.policy;

import cn.tolim.spissatus4j.contract.runtime.HealthStatus;

/** External policy source (file, database, OPA, service) loaded into a snapshot. */
public interface PolicyProvider {

    String providerId();

    PolicySnapshot load();

    default void refresh() {
    }

    HealthStatus health();
}