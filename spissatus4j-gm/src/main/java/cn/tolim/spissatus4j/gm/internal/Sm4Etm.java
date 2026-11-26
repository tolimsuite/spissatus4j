package cn.tolim.spissatus4j.gm.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher.AeadResult;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CTRModeCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Encrypt-then-MAC construction for the non-AEAD SM4 modes.
 *
 * <p>The payload is encrypted with SM4-CBC/PKCS7 or SM4-CTR, then
 * authenticated with HMAC-SM3 under a per-message MAC key derived from the
 * SM4 key and the nonce via RFC 5869 HKDF-SM3. The MAC covers length-prefixed
 * (algorithm identifier, nonce, AAD, ciphertext), so no field boundary can be
 * shifted between messages. Decryption verifies the MAC in constant time
 * before touching the cipher.</p>
 */
public final class Sm4Etm {

    public enum Mode {
        CBC,
        CTR
    }

    public static final int NONCE_LENGTH = 16;
    public static final int TAG_LENGTH = 32;

    private static final byte[] MAC_INFO =
            "spissatus4j/sm4-etm/mac/v1".getBytes(StandardCharsets.UTF_8);

    private Sm4Etm() {
    }

    public static AeadResult encrypt(AlgorithmId algorithm, Mode mode, SecretKey key,
                                     byte[] plaintext, Nonce nonce, AAD aad) {
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(mode, "mode");
        byte[] keyBytes = Sm4Keys.requireKey(key);
        byte[] nonceBytes = Sm4Keys.requireNonce(nonce, NONCE_LENGTH);
        byte[] aadBytes = Sm4Keys.requireAad(aad);
        byte[] plaintextBytes = Sm4Keys.requireBytes(plaintext, "Plaintext");
        byte[] macKey = null;
        try {
            byte[] ciphertext;
            try {
                ciphertext = crypt(mode, true, keyBytes, nonceBytes, plaintextBytes);
            } catch (InvalidCipherTextException | RuntimeException e) {
                throw new CryptoException(ErrorCode.ENCRYPTION_FAILED,
                        "SM4 Encrypt-then-MAC encryption failed");
            }
            macKey = HkdfSm3.derive(keyBytes, nonceBytes, MAC_INFO, TAG_LENGTH);
            byte[] tag = computeTag(macKey, algorithm, nonceBytes, aadBytes, ciphertext);
            return new AeadResult(nonce, ciphertext, tag);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
            Arrays.fill(plaintextBytes, (byte) 0);
            if (macKey != null) {
                Arrays.fill(macKey, (byte) 0);
            }
        }
    }

    public static byte[] decrypt(AlgorithmId algorithm, Mode mode, SecretKey key, Nonce nonce,
                                 byte[] ciphertext, byte[] tag, AAD aad) {
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(mode, "mode");
        byte[] keyBytes = Sm4Keys.requireKey(key);
        byte[] nonceBytes = Sm4Keys.requireNonce(nonce, NONCE_LENGTH);
        byte[] aadBytes = Sm4Keys.requireAad(aad);
        byte[] ciphertextBytes = Sm4Keys.requireBytes(ciphertext, "Ciphertext");
        byte[] tagBytes = tag == null ? null : tag.clone();
        byte[] macKey = null;
        try {
            if (tagBytes == null || tagBytes.length != TAG_LENGTH) {
                throw CryptoException.authenticationFailed(algorithm);
            }
            macKey = HkdfSm3.derive(keyBytes, nonceBytes, MAC_INFO, TAG_LENGTH);
            byte[] expectedTag = computeTag(macKey, algorithm, nonceBytes, aadBytes, ciphertextBytes);
            boolean verified;
            try {
                verified = MessageDigest.isEqual(expectedTag, tagBytes);
            } finally {
                Arrays.fill(expectedTag, (byte) 0);
            }
            if (!verified) {
                throw CryptoException.authenticationFailed(algorithm);
            }
            try {
                return crypt(mode, false, keyBytes, nonceBytes, ciphertextBytes);
            } catch (InvalidCipherTextException | RuntimeException e) {
                throw CryptoException.authenticationFailed(algorithm);
            }
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
            Arrays.fill(ciphertextBytes, (byte) 0);
            if (tagBytes != null) {
                Arrays.fill(tagBytes, (byte) 0);
            }
            if (macKey != null) {
                Arrays.fill(macKey, (byte) 0);
            }
        }
    }

    /**
     * Recomputes the Encrypt-then-MAC tag for a ciphertext. Exposed to this
     * module for self-checks and negative tests only.
     */
    public static byte[] computeTag(AlgorithmId algorithm, SecretKey key, byte[] nonce,
                                    byte[] aad, byte[] ciphertext) {
        Objects.requireNonNull(algorithm, "algorithm");
        if (nonce == null || aad == null || ciphertext == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                    "Nonce, AAD and ciphertext are required");
        }
        byte[] keyBytes = Sm4Keys.requireKey(key);
        try {
            byte[] macKey = HkdfSm3.derive(keyBytes, nonce, MAC_INFO, TAG_LENGTH);
            try {
                return computeTag(macKey, algorithm, nonce, aad, ciphertext);
            } finally {
                Arrays.fill(macKey, (byte) 0);
            }
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    private static byte[] computeTag(byte[] macKey, AlgorithmId algorithm, byte[] nonce,
                                     byte[] aad, byte[] ciphertext) {
        byte[] macInput = macInput(algorithm, nonce, aad, ciphertext);
        try {
            HMac mac = new HMac(new SM3Digest());
            mac.init(new KeyParameter(macKey));
            mac.update(macInput, 0, macInput.length);
            byte[] tag = new byte[TAG_LENGTH];
            mac.doFinal(tag, 0);
            return tag;
        } finally {
            Arrays.fill(macInput, (byte) 0);
        }
    }

    private static byte[] macInput(AlgorithmId algorithm, byte[] nonce, byte[] aad, byte[] ciphertext) {
        byte[] algorithmId = algorithm.id().getBytes(StandardCharsets.UTF_8);
        long totalLength = 4L + algorithmId.length + 4L + nonce.length
                + 4L + aad.length + 4L + ciphertext.length;
        if (totalLength > Integer.MAX_VALUE) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                    "SM4 authentication input is too large");
        }
        ByteBuffer buffer = ByteBuffer.allocate((int) totalLength).order(ByteOrder.BIG_ENDIAN);
        buffer.putInt(algorithmId.length).put(algorithmId);
        buffer.putInt(nonce.length).put(nonce);
        buffer.putInt(aad.length).put(aad);
        buffer.putInt(ciphertext.length).put(ciphertext);
        return buffer.array();
    }

    private static byte[] crypt(Mode mode, boolean forEncryption, byte[] keyBytes, byte[] iv,
                                byte[] input) throws InvalidCipherTextException {
        if (mode == Mode.CBC) {
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                    CBCBlockCipher.newInstance(new SM4Engine()), new PKCS7Padding());
            cipher.init(forEncryption, new ParametersWithIV(new KeyParameter(keyBytes), iv));
            byte[] output = new byte[cipher.getOutputSize(input.length)];
            int written = cipher.processBytes(input, 0, input.length, output, 0);
            written += cipher.doFinal(output, written);
            if (written == output.length) {
                return output;
            }
            byte[] result = Arrays.copyOf(output, written);
            Arrays.fill(output, (byte) 0);
            return result;
        }
        CTRModeCipher cipher = SICBlockCipher.newInstance(new SM4Engine());
        cipher.init(true, new ParametersWithIV(new KeyParameter(keyBytes), iv));
        byte[] output = new byte[input.length];
        int written = cipher.processBytes(input, 0, input.length, output, 0);
        if (written == output.length) {
            return output;
        }
        byte[] result = Arrays.copyOf(output, written);
        Arrays.fill(output, (byte) 0);
        return result;
    }
}