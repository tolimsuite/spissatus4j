package cn.tolim.spissatus4j.crypto.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/** ChaCha20-Poly1305 (RFC 8439) engine backed by the JCA provider. */
final class ChaCha20Poly1305Cipher implements AeadCipher {

    static final int NONCE_BYTES = 12;
    static final int TAG_BYTES = 16;
    private static final String TRANSFORMATION = "ChaCha20-Poly1305";

    @Override
    public AlgorithmId algorithm() {
        return AlgorithmId.CHACHA20_POLY1305;
    }

    @Override
    public int nonceLength() {
        return NONCE_BYTES;
    }

    @Override
    public int tagLength() {
        return TAG_BYTES;
    }

    @Override
    public AeadResult encrypt(SecretKey key, byte[] plaintext, Nonce nonce, AAD aad) {
        byte[] nonceBytes = CryptoSupport.requireNonce(nonce, NONCE_BYTES, algorithm());
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(aad, "aad");
        byte[] keyBytes = CryptoSupport.requireChaChaKey(key, algorithm());
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE,
                    new javax.crypto.spec.SecretKeySpec(keyBytes, "ChaCha20"),
                    new IvParameterSpec(nonceBytes));
            if (!aad.isEmpty()) {
                cipher.updateAAD(aad.asBytes());
            }
            byte[] combined = cipher.doFinal(plaintext);
            int ciphertextLength = combined.length - TAG_BYTES;
            if (ciphertextLength < 0) {
                throw new CryptoException(ErrorCode.ENCRYPTION_FAILED, "ChaCha20-Poly1305 encryption failed");
            }
            byte[] ciphertext = Arrays.copyOf(combined, ciphertextLength);
            byte[] tag = Arrays.copyOfRange(combined, ciphertextLength, combined.length);
            Arrays.fill(combined, (byte) 0);
            return new AeadResult(nonce, ciphertext, tag);
        } catch (GeneralSecurityException e) {
            throw CryptoSupport.providerFailure("ChaCha20-Poly1305 encryption", e);
        } finally {
            CryptoSupport.wipe(keyBytes);
        }
    }

    @Override
    public byte[] decrypt(SecretKey key, Nonce nonce, byte[] ciphertext, byte[] tag, AAD aad) {
        byte[] nonceBytes = CryptoSupport.requireNonce(nonce, NONCE_BYTES, algorithm());
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(tag, "tag");
        Objects.requireNonNull(aad, "aad");
        if (tag.length != TAG_BYTES) {
            throw new CryptoException(ErrorCode.TAG_INVALID,
                    "ChaCha20-Poly1305 authentication tag must be 16 bytes");
        }
        byte[] keyBytes = CryptoSupport.requireChaChaKey(key, algorithm());
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE,
                    new javax.crypto.spec.SecretKeySpec(keyBytes, "ChaCha20"),
                    new IvParameterSpec(nonceBytes));
            if (!aad.isEmpty()) {
                cipher.updateAAD(aad.asBytes());
            }
            cipher.update(ciphertext);
            return cipher.doFinal(tag);
        } catch (AEADBadTagException e) {
            throw CryptoException.authenticationFailed(algorithm());
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.DECRYPTION_FAILED,
                    "ChaCha20-Poly1305 decryption failed", e);
        } finally {
            CryptoSupport.wipe(keyBytes);
        }
    }
}
