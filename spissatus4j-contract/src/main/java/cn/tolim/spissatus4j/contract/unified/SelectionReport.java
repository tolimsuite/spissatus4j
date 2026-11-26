package cn.tolim.spissatus4j.contract.unified;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.key.KeyId;
import java.util.List;
import java.util.Objects;

/**
 * Bounded, non-sensitive record of the selection decision. The selected fields
 * are null only for a failed selection report.
 */
public record SelectionReport(
        String profileId,
        boolean explicit,
        KeyId selectedKeyId,
        AlgorithmId selectedAlgorithm,
        List<CandidateDecision> candidates) {

    public SelectionReport {
        profileId = Objects.requireNonNull(profileId, "profileId");
        candidates = List.copyOf(Objects.requireNonNull(candidates, "candidates"));
    }

    public boolean selected() {
        return selectedKeyId != null && selectedAlgorithm != null;
    }
}