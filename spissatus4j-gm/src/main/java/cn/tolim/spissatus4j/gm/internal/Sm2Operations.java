package cn.tolim.spissatus4j.gm.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Objects;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Lightweight SM2 engine operations shared by the public JCA-facing wrappers,
 * the provider self-check and the known-answer vectors.
 */
public final class Sm2Operations {

    /** GB/T 32918 default user identity. */
    public static final String DEFAULT_USER_ID = "1234567812345678";

    /** Uncompressed C1 (65 bytes) plus C3 (32 bytes) for a non-empty plaintext. */
    public static final int MIN_CIPHERTEXT_LENGTH = 65 + 32;

    /** SM2 plaintext bounds; BC rejects empty input and bulk data is out of scope. */
    public static final int MAX_PLAINTEXT_LENGTH = 1024 * 1024;

    public static final int MAX_CIPHERTEXT_LENGTH = MAX_PLAINTEXT_LENGTH + MIN_CIPHERTEXT_LENGTH;

    private static final byte[] USER_ID = DEFAULT_USER_ID.getBytes(StandardCharsets.US_ASCII);

    private Sm2Operations() {
    }

    public static byte[] encrypt(ECPublicKeyParameters publicKey, byte[] plaintext, SecureRandom random) {
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(random, "random");
        if (plaintext == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "Plaintext is required");
        }
        if (plaintext.length == 0 || plaintext.length > MAX_PLAINTEXT_LENGTH) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                    "SM2 plaintext length is out of bounds");
        }
        requireValidPublicKey(publicKey);
        try {
            SM2Engine engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
            engine.init(true, new ParametersWithRandom(publicKey, random));
            byte[] ciphertext = engine.processBlock(plaintext, 0, plaintext.length);
            if (ciphertext.length != plaintext.length + MIN_CIPHERTEXT_LENGTH || ciphertext[0] != 0x04) {
                throw new CryptoException(ErrorCode.ENCRYPTION_FAILED, "SM2 encryption failed");
            }
            return ciphertext;
        } catch (InvalidCipherTextException | RuntimeException e) {
            if (e instanceof CryptoException cryptoException) {
                throw cryptoException;
            }
            throw new CryptoException(ErrorCode.ENCRYPTION_FAILED, "SM2 encryption failed");
        }
    }

    public static byte[] decrypt(ECPrivateKeyParameters privateKey, byte[] ciphertext) {
        if (privateKey == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "A private key is required");
        }
        if (ciphertext == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "Ciphertext is required");
        }
        if (ciphertext.length < MIN_CIPHERTEXT_LENGTH || ciphertext.length > MAX_CIPHERTEXT_LENGTH) {
            throw CryptoException.authenticationFailed(AlgorithmId.SM2);
        }
        requireValidPrivateKey(privateKey);
        try {
            SM2Engine engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
            engine.init(false, privateKey);
            return engine.processBlock(ciphertext, 0, ciphertext.length);
        } catch (InvalidCipherTextException | RuntimeException e) {
            throw CryptoException.authenticationFailed(AlgorithmId.SM2);
        }
    }

    public static byte[] sign(ECPrivateKeyParameters privateKey, byte[] message, SecureRandom random) {
        if (privateKey == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "A private key is required");
        }
        if (message == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "Message is required");
        }
        Objects.requireNonNull(random, "random");
        requireValidPrivateKey(privateKey);
        try {
            SM2Signer signer = new SM2Signer(new SM3Digest());
            signer.init(true, new ParametersWithID(new ParametersWithRandom(privateKey, random), userId()));
            signer.update(message, 0, message.length);
            return signer.generateSignature();
        } catch (org.bouncycastle.crypto.CryptoException | RuntimeException e) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE, "SM2 signature generation failed");
        }
    }

    public static boolean verify(ECPublicKeyParameters publicKey, byte[] message, byte[] signature) {
        if (publicKey == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "A public key is required");
        }
        if (message == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "Message is required");
        }
        if (signature == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "Signature is required");
        }
        requireValidPublicKey(publicKey);
        try {
            SM2Signer signer = new SM2Signer(new SM3Digest());
            signer.init(false, new ParametersWithID(publicKey, userId()));
            signer.update(message, 0, message.length);
            return signer.verifySignature(signature);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static void requireValidPublicKey(ECPublicKeyParameters publicKey) {
        BcKeyConversion.requireSm2Domain(publicKey.getParameters());
        ECPoint point = publicKey.getQ();
        if (point == null || point.isInfinity() || !point.isValid()) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                    "Key is not an SM2 key on the sm2p256v1 curve");
        }
    }

    private static void requireValidPrivateKey(ECPrivateKeyParameters privateKey) {
        BcKeyConversion.requireSm2Domain(privateKey.getParameters());
        BigInteger scalar = privateKey.getD();
        if (scalar == null || scalar.signum() <= 0
                || scalar.compareTo(privateKey.getParameters().getN()) >= 0) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                    "Key is not an SM2 key on the sm2p256v1 curve");
        }
    }

    private static byte[] userId() {
        return USER_ID.clone();
    }
}