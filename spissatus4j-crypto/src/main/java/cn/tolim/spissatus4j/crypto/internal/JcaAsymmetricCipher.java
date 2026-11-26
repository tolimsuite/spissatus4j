package cn.tolim.spissatus4j.crypto.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/** RSA-OAEP and legacy RSA PKCS#1 v1.5 public-key encryption. */
final class JcaAsymmetricCipher implements AsymmetricCipher {

    private static final int MIN_RSA_BITS = 2048;

    private final AlgorithmId algorithm;
    private final String transformation;
    private final OAEPParameterSpec oaepParameters;

    private JcaAsymmetricCipher(AlgorithmId algorithm, String transformation,
                                OAEPParameterSpec oaepParameters) {
        this.algorithm = algorithm;
        this.transformation = transformation;
        this.oaepParameters = oaepParameters;
    }

    static JcaAsymmetricCipher rsaOaep() {
        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1",
                MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        return new JcaAsymmetricCipher(AlgorithmId.RSA_OAEP,
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", spec);
    }

    static JcaAsymmetricCipher rsaPkcs1() {
        return new JcaAsymmetricCipher(AlgorithmId.RSA_PKCS1,
                "RSA/ECB/PKCS1Padding", null);
    }

    @Override
    public AlgorithmId algorithm() {
        return algorithm;
    }

    @Override
    public byte[] encrypt(PublicKey publicKey, byte[] plaintext) {
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(plaintext, "plaintext");
        requireRsaKeySize(publicKey);
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            if (oaepParameters != null) {
                cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParameters);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            }
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.ENCRYPTION_FAILED,
                    algorithm.id() + " encryption failed", e);
        }
    }

    @Override
    public byte[] decrypt(PrivateKey privateKey, byte[] ciphertext) {
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(ciphertext, "ciphertext");
        requireRsaKeySize(privateKey);
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            if (oaepParameters != null) {
                cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameters);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
            }
            return cipher.doFinal(ciphertext);
        } catch (BadPaddingException e) {
            throw CryptoException.authenticationFailed(algorithm);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.DECRYPTION_FAILED,
                    algorithm.id() + " decryption failed", e);
        }
    }

    private void requireRsaKeySize(Key key) {
        if (!(key instanceof RSAKey rsaKey)) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "RSA key required");
        }
        if (rsaKey.getModulus().bitLength() < MIN_RSA_BITS) {
            throw new CryptoException(ErrorCode.MIN_KEY_BITS_VIOLATION,
                    "RSA keys must be at least " + MIN_RSA_BITS + " bits");
        }
    }
}
