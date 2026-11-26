package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;

/**
 * Key derivation engine for one algorithm family.
 *
 * <p>Exactly one of {@code inputKeyMaterial} and {@code password} is expected:
 * password KDFs consume a char[] password, HKDF consumes input key material.
 * Implementations must clear temporary buffers.</p>
 */
public interface KdfFunction {

    AlgorithmId algorithm();

    byte[] derive(byte[] inputKeyMaterial, char[] password, Salt salt, KdfParameters parameters);

    /** Returns true when persisted parameters are weaker than current defaults. */
    boolean needsRehash(KdfParameters parameters);
}