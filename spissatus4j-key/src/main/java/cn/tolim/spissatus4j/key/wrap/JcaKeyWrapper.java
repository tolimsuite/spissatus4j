package cn.tolim.spissatus4j.key.wrap;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyWrapper;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;

/**
 * JCA-backed data-encryption-key wrapper.
 *
 * <p>One instance wraps one algorithm so that the key manager can select the
 * exact padding or key-wrap mode requested by the caller. RSA uses OAEP with
 * SHA-256/MGF1-SHA-256 or PKCS#1 v1.5; symmetric wrapping uses RFC 3394 AES
 * Key Wrap ({@code AESWrap}, falling back to {@code AES/KW/NoPadding}).</p>
 */
public final class JcaKeyWrapper implements KeyWrapper {

    private static final String RSA_OAEP_TRANSFORMATION =
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String RSA_PKCS1_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String AES_WRAP_TRANSFORMATION = "AESWrap";
    private static final String AES_WRAP_FALLBACK = "AES/KW/NoPadding";

    private final AlgorithmId algorithm;
    private final Set<AlgorithmId> algorithms;

    /**
     * Creates a wrapper for all three documented algorithms. RSA material
     * uses OAEP by default; use {@link #JcaKeyWrapper(AlgorithmId)} to select
     * RSA PKCS#1 v1.5 explicitly.
     */
    public JcaKeyWrapper() {
        this.algorithm = null;
        this.algorithms = Set.of(AlgorithmId.RSA_OAEP, AlgorithmId.RSA_PKCS1,
                AlgorithmId.AES_KW);
    }

    public JcaKeyWrapper(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        if (!algorithm.equals(AlgorithmId.RSA_OAEP) && !algorithm.equals(AlgorithmId.RSA_PKCS1)
                && !algorithm.equals(AlgorithmId.AES_KW)) {
            throw new IllegalArgumentException("Unsupported wrapping algorithm");
        }
        this.algorithm = algorithm;
        this.algorithms = Set.of(algorithm);
    }

    /** Wrappers specialized for each algorithm, suitable for automatic registration. */
    public static List<KeyWrapper> defaults() {
        return List.of(new JcaKeyWrapper(AlgorithmId.RSA_OAEP),
                new JcaKeyWrapper(AlgorithmId.RSA_PKCS1),
                new JcaKeyWrapper(AlgorithmId.AES_KW));
    }

    @Override
    public String wrapperId() {
        return algorithm == null ? "jca-default"
                : "jca-" + algorithm.id().toLowerCase(Locale.ROOT);
    }

    @Override
    public Set<AlgorithmId> algorithms() {
        return algorithms;
    }

    @Override
    public byte[] wrap(PublicKey kek, byte[] dek) {
        Objects.requireNonNull(kek, "kek");
        Objects.requireNonNull(dek, "dek");
        if (!isRsa()) {
            throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION,
                    "Public-key wrapping is not supported by " + wrapperId());
        }
        try {
            return cipher(Cipher.ENCRYPT_MODE, kek).doFinal(dek);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.KEY_WRAP_FAILED, "Key wrapping failed");
        }
    }

    @Override
    public byte[] unwrap(PrivateKey kek, byte[] wrappedDek) {
        Objects.requireNonNull(kek, "kek");
        Objects.requireNonNull(wrappedDek, "wrappedDek");
        if (!isRsa()) {
            throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION,
                    "Private-key unwrapping is not supported by " + wrapperId());
        }
        try {
            return cipher(Cipher.DECRYPT_MODE, kek).doFinal(wrappedDek);
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                 | InvalidAlgorithmParameterException e) {
            throw new CryptoException(ErrorCode.ALGORITHM_UNSUPPORTED,
                    "Wrapping algorithm is not available");
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw CryptoException.authenticationFailed(authenticationAlgorithm(false));
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.KEY_WRAP_FAILED, "Key unwrapping failed");
        }
    }

    @Override
    public byte[] wrap(SecretKey kek, byte[] dek) {
        Objects.requireNonNull(kek, "kek");
        Objects.requireNonNull(dek, "dek");
        if (!isAesKeyWrap()) {
            throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION,
                    "Symmetric wrapping is not supported by " + wrapperId());
        }
        try {
            return aesWrapCipher(Cipher.ENCRYPT_MODE, kek).doFinal(dek);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.KEY_WRAP_FAILED, "Key wrapping failed");
        }
    }

    @Override
    public byte[] unwrap(SecretKey kek, byte[] wrappedDek) {
        Objects.requireNonNull(kek, "kek");
        Objects.requireNonNull(wrappedDek, "wrappedDek");
        if (!isAesKeyWrap()) {
            throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION,
                    "Symmetric unwrapping is not supported by " + wrapperId());
        }
        try {
            return aesWrapCipher(Cipher.DECRYPT_MODE, kek).doFinal(wrappedDek);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new CryptoException(ErrorCode.ALGORITHM_UNSUPPORTED,
                    "Wrapping algorithm is not available");
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw CryptoException.authenticationFailed(authenticationAlgorithm(true));
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.KEY_WRAP_FAILED, "Key unwrapping failed");
        }
    }

    @Override
    public HealthStatus health() {
        boolean aesWrapAvailable = cipherAvailable(AES_WRAP_TRANSFORMATION)
                || cipherAvailable(AES_WRAP_FALLBACK);
        boolean oaepAvailable = cipherAvailable(RSA_OAEP_TRANSFORMATION);
        boolean pkcs1Available = cipherAvailable(RSA_PKCS1_TRANSFORMATION);
        boolean healthy = (!isAesKeyWrap() || aesWrapAvailable)
                && (!isRsaOaep() || oaepAvailable)
                && (!isRsaPkcs1() || pkcs1Available);
        return healthy ? HealthStatus.UP : HealthStatus.DOWN;
    }

    private static boolean cipherAvailable(String transformation) {
        try {
            Cipher.getInstance(transformation);
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private Cipher cipher(int mode, java.security.Key key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(transformation());
        if (isRsaOaep()) {
            OAEPParameterSpec parameters = new OAEPParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            cipher.init(mode, key, parameters);
        } else {
            cipher.init(mode, key);
        }
        return cipher;
    }

    private Cipher aesWrapCipher(int mode, SecretKey key) throws GeneralSecurityException {
        try {
            Cipher cipher = Cipher.getInstance(AES_WRAP_TRANSFORMATION);
            cipher.init(mode, key);
            return cipher;
        } catch (NoSuchAlgorithmException e) {
            Cipher cipher = Cipher.getInstance(AES_WRAP_FALLBACK);
            cipher.init(mode, key);
            return cipher;
        }
    }

    private String transformation() {
        return isRsaOaep() ? RSA_OAEP_TRANSFORMATION : RSA_PKCS1_TRANSFORMATION;
    }

    private boolean isRsaOaep() {
        return algorithm == null || algorithm.equals(AlgorithmId.RSA_OAEP);
    }

    private boolean isRsaPkcs1() {
        return algorithm == null || algorithm.equals(AlgorithmId.RSA_PKCS1);
    }

    private boolean isRsa() {
        return isRsaOaep() || isRsaPkcs1();
    }

    private boolean isAesKeyWrap() {
        return algorithm == null || algorithm.equals(AlgorithmId.AES_KW);
    }

    private AlgorithmId authenticationAlgorithm(boolean symmetric) {
        if (algorithm != null) {
            return algorithm;
        }
        return symmetric ? AlgorithmId.AES_KW : AlgorithmId.RSA_OAEP;
    }
}