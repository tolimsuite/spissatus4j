package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Objects;

/**
 * Reserved hybrid-KEM contract: two or more independent KEM encapsulations
 * whose shared secrets are combined into one key. Implementations must use a
 * standard combiner (for example HKDF over the concatenated secrets and the
 * full transcript) and must fail if any component fails; a hybrid must never
 * downgrade to a single component.
 */
public interface HybridKem {

    AlgorithmId algorithm();

    List<AlgorithmId> componentAlgorithms();

    HybridEncapsulation encapsulate(List<PublicKey> publicKeys);

    byte[] decapsulate(List<PrivateKey> privateKeys, List<byte[]> encapsulations);

    /** Per-component encapsulations plus the combined shared secret. */
    record HybridEncapsulation(List<byte[]> encapsulations, byte[] sharedSecret) {

        public HybridEncapsulation {
            Objects.requireNonNull(encapsulations, "encapsulations");
            List<byte[]> copies = new java.util.ArrayList<>(encapsulations.size());
            for (byte[] encapsulation : encapsulations) {
                copies.add(Objects.requireNonNull(encapsulation, "encapsulation").clone());
            }
            encapsulations = List.copyOf(copies);
            sharedSecret = Objects.requireNonNull(sharedSecret, "sharedSecret").clone();
        }

        @Override
        public List<byte[]> encapsulations() {
            List<byte[]> copies = new java.util.ArrayList<>(encapsulations.size());
            for (byte[] encapsulation : encapsulations) {
                copies.add(encapsulation.clone());
            }
            return List.copyOf(copies);
        }

        @Override
        public byte[] sharedSecret() {
            return sharedSecret.clone();
        }

        @Override
        public String toString() {
            return "HybridEncapsulation[components=" + encapsulations.size()
                    + ", sharedSecretLength=" + sharedSecret.length + "]";
        }
    }
}