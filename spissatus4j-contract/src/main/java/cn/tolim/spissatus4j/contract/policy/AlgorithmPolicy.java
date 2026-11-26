package cn.tolim.spissatus4j.contract.policy;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import java.util.Set;

/** Algorithm whitelist/blacklist, lifecycle and minimum key-size policy. */
public interface AlgorithmPolicy extends PolicyRule {

    Set<AlgorithmId> allowedAlgorithms();

    Set<AlgorithmId> deniedAlgorithms();

    int minimumKeyBits(AlgorithmId algorithm);

    PolicyDecision evaluate(PolicyRequest request);
}