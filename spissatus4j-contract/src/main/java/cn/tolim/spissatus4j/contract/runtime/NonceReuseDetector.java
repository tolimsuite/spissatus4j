package cn.tolim.spissatus4j.contract.runtime;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.Nonce;

/**
 * Detects reuse of a Nonce/IV under the same algorithm. A storage failure must
 * be treated as fail-closed by the caller.
 */
public interface NonceReuseDetector {

    /**
     * Registers a nonce.
     *
     * @return {@code true} when the nonce was already registered (reuse)
     */
    boolean register(AlgorithmId algorithm, Nonce nonce);

    void clear();

    HealthStatus health();

    int size();
}