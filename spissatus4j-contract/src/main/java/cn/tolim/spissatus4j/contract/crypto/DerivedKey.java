package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import java.util.Objects;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Result of a key derivation. Bytes are copied on access; {@code toString}
 * never reveals them.
 */
public final class DerivedKey {

    private final AlgorithmId algorithm;
    private final byte[] key;
    private final Salt salt;
    private final KdfParameters parameters;
    private final boolean needsRehash;

    public DerivedKey(AlgorithmId algorithm, byte[] key, Salt salt, KdfParameters parameters,
                      boolean needsRehash) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.key = Objects.requireNonNull(key, "key").clone();
        this.salt = Objects.requireNonNull(salt, "salt");
        this.parameters = Objects.requireNonNull(parameters, "parameters");
        this.needsRehash = needsRehash;
    }

    public AlgorithmId algorithm() {
        return algorithm;
    }

    public byte[] key() {
        return key.clone();
    }

    public int length() {
        return key.length;
    }

    public Salt salt() {
        return salt;
    }

    public KdfParameters parameters() {
        return parameters;
    }

    public boolean needsRehash() {
        return needsRehash;
    }

    /** Converts to a JCA secret key for direct use with an engine. */
    public SecretKey toSecretKey(String jcaAlgorithm) {
        return new SecretKeySpec(key, Objects.requireNonNull(jcaAlgorithm, "jcaAlgorithm"));
    }

    @Override
    public String toString() {
        return "DerivedKey[algorithm=" + algorithm + ", length=" + key.length
                + ", needsRehash=" + needsRehash + "]";
    }
}