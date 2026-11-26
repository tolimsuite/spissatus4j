package cn.tolim.spissatus4j.contract.algorithm;

/**
 * Security posture of an algorithm as of the catalog version.
 *
 * <p>Unknown algorithms are always treated as {@link #UNKNOWN}, which the
 * default policy denies. Deprecated algorithms produce a warning by default;
 * prohibited algorithms are always denied.</p>
 */
public enum SecurityStatus {
    RECOMMENDED,
    ACCEPTABLE,
    EXPERIMENTAL,
    DEPRECATED,
    PROHIBITED,
    UNKNOWN
}