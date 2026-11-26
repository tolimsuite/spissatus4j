package cn.tolim.spissatus4j.bc.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;

/**
 * RSA-OAEP engine with an explicit SHA-256 / MGF1-SHA-256 parameter set.
 * Decryption padding failures are indistinguishable from other authentication
 * failures and never include provider detail.
 *
 * <p>Internal type; not part of the public API.</p>
 */
public final class BcAsymmetricCipher implements AsymmetricCipher {

    private static final String TRANSFORMATION = "RSA/ECB/OAEPPadding";
    private static final OAEPParameterSpec OAEP_SHA256 = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private final AlgorithmId algorithm;
    private final Provider provider;

    public BcAsymmetricCipher(AlgorithmId algorithm, Provider provider) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.provider = Objects.requireNonNull(provider, "provider");
    }

    @Override
    public AlgorithmId algorithm() {
        return algorithm;
    }

    @Override
    public byte[] encrypt(PublicKey publicKey, byte[] plaintext) {
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(plaintext, "plaintext");
        int maxPlaintextBytes = maxOaepPlaintextBytes(publicKey);
        if (maxPlaintextBytes >= 0 && plaintext.length > maxPlaintextBytes) {
            throw new CryptoException(ErrorCode.ENCRYPTION_FAILED, "RSA-OAEP encryption failed");
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION, provider);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_SHA256);
            return cipher.doFinal(plaintext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw BcProviders.providerFailure("RSA-OAEP cipher is unavailable");
        } catch (InvalidKeyException e) {
            throw BcProviders.invalidParameter("Invalid RSA public key");
        } catch (InvalidAlgorithmParameterException e) {
            throw BcProviders.providerFailure("RSA-OAEP parameters are not supported");
        } catch (IllegalBlockSizeException | BadPaddingException | ArrayIndexOutOfBoundsException e) {
            throw new CryptoException(ErrorCode.ENCRYPTION_FAILED, "RSA-OAEP encryption failed");
        }
    }

    @Override
    public byte[] decrypt(PrivateKey privateKey, byte[] ciphertext) {
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(ciphertext, "ciphertext");
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION, provider);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP_SHA256);
            return cipher.doFinal(ciphertext);
        } catch (BadPaddingException e) {
            throw CryptoException.authenticationFailed(algorithm);
        } catch (IllegalBlockSizeException | ArrayIndexOutOfBoundsException e) {
            throw new CryptoException(ErrorCode.INVALID_CIPHERTEXT, "Invalid RSA ciphertext");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw BcProviders.providerFailure("RSA-OAEP cipher is unavailable");
        } catch (InvalidKeyException e) {
            throw BcProviders.invalidParameter("Invalid RSA private key");
        } catch (InvalidAlgorithmParameterException e) {
            throw BcProviders.providerFailure("RSA-OAEP parameters are not supported");
        } catch (CryptoException e) {
            throw e;
        } catch (RuntimeException e) {
            // BC's RSA core throws an unchecked DataLengthException when the
            // ciphertext integer is >= the modulus. Never let provider detail
            // distinguish that case from a normal padding failure.
            throw CryptoException.authenticationFailed(algorithm);
        }
    }

    /**
     * Returns the largest OAEP-SHA256 plaintext for an RSA key (modulus size
     * minus 2 * 32-byte hash minus 2), or -1 when the key is not an RSA key.
     */
    private static int maxOaepPlaintextBytes(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey rsaKey) {
            int modulusBytes = (rsaKey.getModulus().bitLength() + 7) / 8;
            return modulusBytes - 2 * SHA256_BYTES - 2;
        }
        return -1;
    }

    private static final int SHA256_BYTES = 32;
}