package cn.tolim.spissatus4j.bc.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * ECIES engine backed by the Bouncy Castle JCA provider.
 *
 * <p>The JCA {@code ECIES} transformation writes the ephemeral public key into
 * the ciphertext, so callers only need to transport the returned byte array.
 * Every decryption failure (wrong key, tampered ephemeral point, truncated or
 * malformed ciphertext, provider-level unchecked failures) is reported as a
 * single generic authentication failure without provider detail.</p>
 *
 * <p>Internal type; not part of the public API.</p>
 */
public final class BcEciesCipher implements AsymmetricCipher {

    private static final String TRANSFORMATION = "ECIES";

    private final AlgorithmId algorithm;
    private final Provider provider;

    public BcEciesCipher(AlgorithmId algorithm, Provider provider) {
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
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION, provider);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(plaintext);
        } catch (CryptoException e) {
            throw e;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw BcProviders.providerFailure("ECIES cipher is unavailable");
        } catch (InvalidKeyException e) {
            throw BcProviders.invalidParameter("Invalid EC public key");
        } catch (IllegalBlockSizeException | BadPaddingException | RuntimeException e) {
            throw new CryptoException(ErrorCode.ENCRYPTION_FAILED, "ECIES encryption failed");
        }
    }

    @Override
    public byte[] decrypt(PrivateKey privateKey, byte[] ciphertext) {
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(ciphertext, "ciphertext");
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION, provider);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(ciphertext);
        } catch (CryptoException e) {
            throw e;
        } catch (BadPaddingException e) {
            throw CryptoException.authenticationFailed(algorithm);
        } catch (IllegalBlockSizeException | ArrayIndexOutOfBoundsException e) {
            throw CryptoException.authenticationFailed(algorithm);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw BcProviders.providerFailure("ECIES cipher is unavailable");
        } catch (InvalidKeyException e) {
            throw BcProviders.invalidParameter("Invalid EC private key");
        } catch (RuntimeException e) {
            throw CryptoException.authenticationFailed(algorithm);
        }
    }
}