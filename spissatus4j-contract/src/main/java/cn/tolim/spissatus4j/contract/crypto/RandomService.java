package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.util.UUID;

/**
 * CSPRNG-backed randomness. {@code java.util.Random}, {@code Math.random} and
 * deterministic PRNGs are forbidden.
 */
public interface RandomService {

    byte[] nextBytes(int length);

    String nextBase64(int byteLength);

    String nextUrlSafeToken(int byteLength);

    UUID nextUuid();

    Nonce nextNonce(AlgorithmId algorithm);

    Salt nextSalt(int byteLength);

    HealthStatus health();
}