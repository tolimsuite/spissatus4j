package cn.tolim.spissatus4j.contract.unified;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.key.KeyId;
import java.util.Objects;

/** One evaluated algorithm/key candidate and its stable outcome. */
public record CandidateDecision(
        KeyId keyId,
        AlgorithmId algorithm,
        boolean selected,
        SelectionRejection outcome) {

    public CandidateDecision {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(outcome, "outcome");
    }

    @Override
    public String toString() {
        return "CandidateDecision[keyId=" + keyId + ", algorithm=" + algorithm
                + ", selected=" + selected + ", outcome=" + outcome + "]";
    }
}