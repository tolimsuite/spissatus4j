package cn.tolim.spissatus4j.contract.compliance;

import cn.tolim.spissatus4j.contract.algorithm.SecurityStatus;

/** Long-term algorithm lifecycle used by compliance and deprecation processes. */
public enum AlgorithmLifecycle {
    DRAFT,
    ACTIVE,
    DEPRECATED,
    RETIRED,
    PROHIBITED;

    public static AlgorithmLifecycle from(SecurityStatus status) {
        return switch (status) {
            case RECOMMENDED, ACCEPTABLE -> ACTIVE;
            case EXPERIMENTAL -> DRAFT;
            case DEPRECATED -> DEPRECATED;
            case PROHIBITED -> PROHIBITED;
            case UNKNOWN -> RETIRED;
        };
    }

    public boolean usableForNewData() {
        return this == ACTIVE;
    }
}