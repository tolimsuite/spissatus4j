package cn.tolim.spissatus4j.contract.crypto;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import java.util.Objects;
import javax.crypto.SecretKey;

/**
 * Authenticated encryption engine. All non-AEAD block modes exposed by this
 * library are wrapped with Encrypt-then-MAC and implement this same interface.
 * Callers supply the nonce so the runtime can perform reuse detection before
 * encryption.
 */
public interface AeadCipher {

    AlgorithmId algorithm();

    int nonceLength();

    int tagLength();

    AeadResult encrypt(SecretKey key, byte[] plaintext, Nonce nonce, AAD aad);

    /**
     * Verifies and decrypts. Implementations must throw a generic
     * {@link cn.tolim.spissatus4j.contract.exception.CryptoException#authenticationFailed(AlgorithmId)}
     * on tag failure.
     */
    byte[] decrypt(SecretKey key, Nonce nonce, byte[] ciphertext, byte[] tag, AAD aad);

    /** Raw encryption output; the facade attaches key metadata. */
    record AeadResult(Nonce nonce, byte[] ciphertext, byte[] tag) {

        public AeadResult {
            Objects.requireNonNull(nonce, "nonce");
            ciphertext = Objects.requireNonNull(ciphertext, "ciphertext").clone();
            tag = Objects.requireNonNull(tag, "tag").clone();
        }

        @Override
        public byte[] ciphertext() {
            return ciphertext.clone();
        }

        @Override
        public byte[] tag() {
            return tag.clone();
        }
    }
}