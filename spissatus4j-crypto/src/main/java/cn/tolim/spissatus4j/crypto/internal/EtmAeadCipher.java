package cn.tolim.spissatus4j.crypto.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypt-then-MAC wrapper for AES block modes. The per-message MAC key is
 * derived with HKDF-SHA256 from the encryption key and nonce; the tag is
 * verified in constant time before any decryption is attempted.
 */
final class EtmAeadCipher implements AeadCipher {

    private static final byte[] HKDF_INFO = CryptoSupport.utf8("spissatus4j/etm/mac/v1");
    private static final int MAC_KEY_BYTES = 32;
    private static final int TAG_BYTES = 32;
    private static final int NONCE_BYTES = 16;
    private static final String MAC_ALGORITHM = "HmacSHA256";

    private final AlgorithmId algorithm;
    private final String transformation;

    EtmAeadCipher(AlgorithmId algorithm, String transformation) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.transformation = Objects.requireNonNull(transformation, "transformation");
    }

    @Override
    public AlgorithmId algorithm() {
        return algorithm;
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
        byte[] nonceBytes = CryptoSupport.requireNonce(nonce, NONCE_BYTES, algorithm);
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(aad, "aad");
        byte[] aadBytes = aad.asBytes();
        byte[] keyBytes = CryptoSupport.requireAesKey(key, algorithm);
        byte[] macKey = null;
        try {
            byte[] ciphertext;
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new IvParameterSpec(nonceBytes));
            ciphertext = cipher.doFinal(plaintext);
            macKey = HkdfFunction.derive(keyBytes, nonceBytes, HKDF_INFO, MAC_KEY_BYTES, MAC_ALGORITHM);
            byte[] tag = computeTag(macKey, algorithm, nonceBytes, aadBytes, ciphertext);
            return new AeadResult(nonce, ciphertext, tag);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.ENCRYPTION_FAILED,
                    algorithm.id() + " encryption failed", e);
        } finally {
            CryptoSupport.wipe(macKey);
            CryptoSupport.wipe(keyBytes);
            CryptoSupport.wipe(aadBytes);
        }
    }

    @Override
    public byte[] decrypt(SecretKey key, Nonce nonce, byte[] ciphertext, byte[] tag, AAD aad) {
        byte[] nonceBytes = CryptoSupport.requireNonce(nonce, NONCE_BYTES, algorithm);
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(tag, "tag");
        Objects.requireNonNull(aad, "aad");
        byte[] aadBytes = aad.asBytes();
        byte[] keyBytes = CryptoSupport.requireAesKey(key, algorithm);
        byte[] macKey = null;
        try {
            if (tag.length != TAG_BYTES) {
                throw CryptoException.authenticationFailed(algorithm);
            }
            macKey = HkdfFunction.derive(keyBytes, nonceBytes, HKDF_INFO, MAC_KEY_BYTES, MAC_ALGORITHM);
            byte[] expected = computeTag(macKey, algorithm, nonceBytes, aadBytes, ciphertext);
            boolean valid;
            try {
                valid = MessageDigest.isEqual(expected, tag);
            } finally {
                CryptoSupport.wipe(expected);
            }
            if (!valid) {
                throw CryptoException.authenticationFailed(algorithm);
            }
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new IvParameterSpec(nonceBytes));
            return cipher.doFinal(ciphertext);
        } catch (CryptoException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            // The tag has already been verified; never expose a distinct failure
            // mode for anything that happens afterwards.
            throw CryptoException.authenticationFailed(algorithm);
        } finally {
            CryptoSupport.wipe(macKey);
            CryptoSupport.wipe(keyBytes);
            CryptoSupport.wipe(aadBytes);
        }
    }

    private static byte[] computeTag(byte[] macKey, AlgorithmId algorithm, byte[] nonce,
                                     byte[] aad, byte[] ciphertext) {
        try {
            Mac mac = Mac.getInstance(MAC_ALGORITHM);
            mac.init(new SecretKeySpec(macKey, MAC_ALGORITHM));
            updateField(mac, CryptoSupport.utf8(algorithm.id()));
            updateField(mac, nonce);
            updateField(mac, aad);
            updateField(mac, ciphertext);
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE, "EtM tag computation failed", e);
        }
    }

    /** Length-prefixes one field so concatenations can never be ambiguous. */
    private static void updateField(Mac mac, byte[] value) {
        int length = value.length;
        mac.update((byte) (length >>> 24));
        mac.update((byte) (length >>> 16));
        mac.update((byte) (length >>> 8));
        mac.update((byte) length);
        mac.update(value);
    }
}
