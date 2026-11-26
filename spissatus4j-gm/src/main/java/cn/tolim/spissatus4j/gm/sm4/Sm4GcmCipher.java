package cn.tolim.spissatus4j.gm.sm4;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.gm.internal.Sm4Keys;
import java.util.Arrays;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/** SM4-GCM with a 96-bit nonce, a 128-bit tag and a 128-bit key. */
public final class Sm4GcmCipher implements AeadCipher {

    public static final int NONCE_LENGTH = 12;
    public static final int TAG_LENGTH = 16;

    @Override
    public AlgorithmId algorithm() {
        return AlgorithmId.SM4_GCM;
    }

    @Override
    public int nonceLength() {
        return NONCE_LENGTH;
    }

    @Override
    public int tagLength() {
        return TAG_LENGTH;
    }

    @Override
    public AeadResult encrypt(SecretKey key, byte[] plaintext, Nonce nonce, AAD aad) {
        byte[] keyBytes = Sm4Keys.requireKey(key);
        byte[] nonceBytes = Sm4Keys.requireNonce(nonce, NONCE_LENGTH);
        byte[] aadBytes = Sm4Keys.requireAad(aad);
        byte[] plaintextBytes = Sm4Keys.requireBytes(plaintext, "Plaintext");
        try {
            byte[] output;
            try {
                GCMModeCipher cipher = GCMBlockCipher.newInstance(new SM4Engine());
                cipher.init(true, new AEADParameters(new KeyParameter(keyBytes),
                        TAG_LENGTH * 8, nonceBytes, aadBytes));
                output = new byte[cipher.getOutputSize(plaintextBytes.length)];
                int written = cipher.processBytes(plaintextBytes, 0, plaintextBytes.length, output, 0);
                written += cipher.doFinal(output, written);
                if (written != plaintextBytes.length + TAG_LENGTH) {
                    throw new CryptoException(ErrorCode.ENCRYPTION_FAILED, "SM4-GCM encryption failed");
                }
            } catch (InvalidCipherTextException | RuntimeException e) {
                throw new CryptoException(ErrorCode.ENCRYPTION_FAILED, "SM4-GCM encryption failed");
            }
            int ciphertextLength = output.length - TAG_LENGTH;
            byte[] ciphertext = Arrays.copyOf(output, ciphertextLength);
            byte[] tag = Arrays.copyOfRange(output, ciphertextLength, output.length);
            Arrays.fill(output, (byte) 0);
            return new AeadResult(nonce, ciphertext, tag);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
            Arrays.fill(plaintextBytes, (byte) 0);
        }
    }

    @Override
    public byte[] decrypt(SecretKey key, Nonce nonce, byte[] ciphertext, byte[] tag, AAD aad) {
        byte[] keyBytes = Sm4Keys.requireKey(key);
        byte[] nonceBytes = Sm4Keys.requireNonce(nonce, NONCE_LENGTH);
        byte[] aadBytes = Sm4Keys.requireAad(aad);
        byte[] ciphertextBytes = Sm4Keys.requireBytes(ciphertext, "Ciphertext");
        byte[] tagBytes = tag == null ? null : tag.clone();
        try {
            if (tagBytes == null || tagBytes.length != TAG_LENGTH) {
                throw CryptoException.authenticationFailed(AlgorithmId.SM4_GCM);
            }
            byte[] combined = new byte[ciphertextBytes.length + TAG_LENGTH];
            System.arraycopy(ciphertextBytes, 0, combined, 0, ciphertextBytes.length);
            System.arraycopy(tagBytes, 0, combined, ciphertextBytes.length, TAG_LENGTH);
            try {
                GCMModeCipher cipher = GCMBlockCipher.newInstance(new SM4Engine());
                cipher.init(false, new AEADParameters(new KeyParameter(keyBytes),
                        TAG_LENGTH * 8, nonceBytes, aadBytes));
                byte[] output = new byte[Math.max(0, cipher.getOutputSize(combined.length))];
                try {
                    int written = cipher.processBytes(combined, 0, combined.length, output, 0);
                    written += cipher.doFinal(output, written);
                    return Arrays.copyOf(output, written);
                } finally {
                    Arrays.fill(output, (byte) 0);
                }
            } catch (InvalidCipherTextException | RuntimeException e) {
                throw CryptoException.authenticationFailed(AlgorithmId.SM4_GCM);
            } finally {
                Arrays.fill(combined, (byte) 0);
            }
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
            Arrays.fill(ciphertextBytes, (byte) 0);
            if (tagBytes != null) {
                Arrays.fill(tagBytes, (byte) 0);
            }
        }
    }
}