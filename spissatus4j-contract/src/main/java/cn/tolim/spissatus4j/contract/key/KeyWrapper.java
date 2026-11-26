package cn.tolim.spissatus4j.contract.key;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Set;
import javax.crypto.SecretKey;

/**
 * Wraps and unwraps data encryption keys (DEKs) under a key-encryption key
 * (KEK). Implementations must not expose the plaintext DEK to business code.
 */
public interface KeyWrapper {

    String wrapperId();

    Set<AlgorithmId> algorithms();

    default boolean supports(AlgorithmId algorithm) {
        return algorithms().contains(algorithm);
    }

    byte[] wrap(PublicKey kek, byte[] dek);

    byte[] unwrap(PrivateKey kek, byte[] wrappedDek);

    default byte[] wrap(SecretKey kek, byte[] dek) {
        throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION,
                "Symmetric wrapping is not supported by " + wrapperId());
    }

    default byte[] unwrap(SecretKey kek, byte[] wrappedDek) {
        throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION,
                "Symmetric unwrapping is not supported by " + wrapperId());
    }

    default HealthStatus health() {
        return HealthStatus.UP;
    }
}