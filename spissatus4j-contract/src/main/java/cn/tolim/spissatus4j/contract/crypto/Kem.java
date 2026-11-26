package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Key encapsulation mechanism. Reserved for post-quantum and hybrid
 * deployments; the catalog marks ML-KEM-768 as experimental and the default
 * policy denies experimental algorithms until explicitly enabled.
 */
public interface Kem {

    AlgorithmId algorithm();

    KemResult encapsulate(PublicKey publicKey);

    byte[] decapsulate(PrivateKey privateKey, byte[] encapsulation);

    /** Encapsulation ciphertext and the shared secret it protects. */
    record KemResult(byte[] encapsulation, byte[] sharedSecret) {

        public KemResult {
            encapsulation = Objects.requireNonNull(encapsulation, "encapsulation").clone();
            sharedSecret = Objects.requireNonNull(sharedSecret, "sharedSecret").clone();
        }

        @Override
        public byte[] encapsulation() {
            return encapsulation.clone();
        }

        @Override
        public byte[] sharedSecret() {
            return sharedSecret.clone();
        }

        @Override
        public String toString() {
            return "KemResult[encapsulationLength=" + encapsulation.length
                    + ", sharedSecretLength=" + sharedSecret.length + "]";
        }
    }
}