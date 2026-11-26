package cn.tolim.spissatus4j.contract.unified;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmInfo;
import java.util.Objects;

/**
 * Read-only capability view of one algorithm in the current configuration.
 *
 * @param info catalog metadata
 * @param installed at least one usable provider declares support
 * @param compliant allowed by the active compliance mode
 * @param available installed, compliant and at least one provider is healthy
 * @param rank position in the default profile order, or -1
 */
public record AlgorithmCandidate(
        AlgorithmInfo info,
        boolean installed,
        boolean compliant,
        boolean available,
        int rank) {

    public AlgorithmCandidate {
        Objects.requireNonNull(info, "info");
        if (rank < -1) {
            throw new IllegalArgumentException("rank must be -1 or non-negative");
        }
    }

    @Override
    public String toString() {
        return "AlgorithmCandidate[id=" + info.id() + ", installed=" + installed
                + ", compliant=" + compliant + ", available=" + available
                + ", rank=" + rank + "]";
    }
}