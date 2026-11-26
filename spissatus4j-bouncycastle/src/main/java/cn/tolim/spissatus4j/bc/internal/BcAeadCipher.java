package cn.tolim.spissatus4j.bc.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * AEAD engine backed by the Bouncy Castle JCA provider.
 *
 * <p>Supports AES-GCM and ChaCha20-Poly1305. Nonces are 12 bytes, tags are
 * 16 bytes. The ciphertext deliberately excludes the tag; the contract
 * transports both separately. Tag verification is performed by the JCA
 * implementation inside {@link Cipher#doFinal(byte[])} and every
 * authentication failure is mapped to a generic failure without detail.</p>
 *
 * <p>Internal type; not part of the public API.</p>
 */
public final class BcAeadCipher implements AeadCipher {

    private static final int NONCE_BYTES = 12;
    private static final int TAG_BYTES = 16;
    private static final int TAG_BITS = TAG_BYTES * 8;

    private final AlgorithmId algorithm;
    private final String transformation;
    private final Provider provider;

    public BcAeadCipher(AlgorithmId algorithm, String transformation, Provider provider) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.transformation = Objects.requireNonNull(transformation, "transformation");
        this.provider = Objects.requireNonNull(provider, "provider");
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
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(aad, "aad");
        byte[] nonceBytes = nonce.asBytes();
        checkNonceLength(nonceBytes);
        try {
            Cipher cipher = Cipher.getInstance(transformation, provider);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonceBytes));
            cipher.updateAAD(aad.asBytes());
            byte[] combined = cipher.doFinal(plaintext);
            byte[] ciphertext = Arrays.copyOf(combined, combined.length - TAG_BYTES);
            byte[] tag = Arrays.copyOfRange(combined, combined.length - TAG_BYTES, combined.length);
            Arrays.fill(combined, (byte) 0);
            return new AeadResult(nonce, ciphertext, tag);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw BcProviders.providerFailure("AEAD cipher is unavailable");
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw BcProviders.invalidParameter("Invalid AEAD key or parameters");
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException(ErrorCode.ENCRYPTION_FAILED, "AEAD encryption failed");
        } finally {
            Arrays.fill(nonceBytes, (byte) 0);
        }
    }

    @Override
    public byte[] decrypt(SecretKey key, Nonce nonce, byte[] ciphertext, byte[] tag, AAD aad) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(tag, "tag");
        Objects.requireNonNull(aad, "aad");
        if (tag.length != TAG_BYTES) {
            throw new CryptoException(ErrorCode.TAG_INVALID, "Invalid authentication tag length");
        }
        byte[] nonceBytes = nonce.asBytes();
        checkNonceLength(nonceBytes);
        byte[] combined = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
        System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);
        try {
            Cipher cipher = Cipher.getInstance(transformation, provider);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonceBytes));
            cipher.updateAAD(aad.asBytes());
            return cipher.doFinal(combined);
        } catch (AEADBadTagException e) {
            throw CryptoException.authenticationFailed(algorithm);
        } catch (BadPaddingException e) {
            throw CryptoException.authenticationFailed(algorithm);
        } catch (IllegalBlockSizeException e) {
            throw new CryptoException(ErrorCode.INVALID_CIPHERTEXT, "Invalid AEAD ciphertext");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw BcProviders.providerFailure("AEAD cipher is unavailable");
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw BcProviders.invalidParameter("Invalid AEAD key or parameters");
        } finally {
            Arrays.fill(combined, (byte) 0);
            Arrays.fill(nonceBytes, (byte) 0);
        }
    }

    private static void checkNonceLength(byte[] nonceBytes) {
        if (nonceBytes.length != NONCE_BYTES) {
            throw new CryptoException(ErrorCode.NONCE_INVALID, "AEAD nonces must be 12 bytes");
        }
    }
}