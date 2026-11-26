package cn.tolim.spissatus4j.contract.spi;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.contract.crypto.HashFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfFunction;
import cn.tolim.spissatus4j.contract.crypto.Kem;
import cn.tolim.spissatus4j.contract.crypto.MacFunction;
import cn.tolim.spissatus4j.contract.crypto.SignatureFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckable;
import java.util.Set;

/**
 * Supplies concrete cryptographic engines. Implementations are trusted
 * extension points and must run a known-answer self-check at startup.
 *
 * <p>Higher {@link #priority()} values are preferred when multiple providers
 * support the same algorithm.</p>
 */
public interface AlgorithmProvider extends SelfCheckable, AutoCloseable {

    String providerId();

    default int priority() {
        return 100;
    }

    Set<AlgorithmId> supportedAlgorithms();

    default boolean supports(AlgorithmId algorithm) {
        return supportedAlgorithms().contains(algorithm);
    }

    /**
     * True only when every engine from this provider runs inside a validated
     * FIPS provider boundary. The facade refuses non-FIPS-capable providers
     * while the compliance mode is {@code FIPS}.
     */
    default boolean fipsCapable() {
        return false;
    }

    AeadCipher aeadCipher(AlgorithmId algorithm);

    AsymmetricCipher asymmetricCipher(AlgorithmId algorithm);

    HashFunction hash(AlgorithmId algorithm);

    MacFunction mac(AlgorithmId algorithm);

    SignatureFunction signature(AlgorithmId algorithm);

    KdfFunction kdf(AlgorithmId algorithm);

    /** Reserved post-quantum/hybrid KEM engine; unsupported by default. */
    default Kem kem(AlgorithmId algorithm) {
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    default void close() {
    }
}