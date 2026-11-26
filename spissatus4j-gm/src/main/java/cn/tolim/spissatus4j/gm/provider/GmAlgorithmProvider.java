package cn.tolim.spissatus4j.gm.provider;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.contract.crypto.HashFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfFunction;
import cn.tolim.spissatus4j.contract.crypto.MacFunction;
import cn.tolim.spissatus4j.contract.crypto.SignatureFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckResult;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.gm.internal.BcKeyConversion;
import cn.tolim.spissatus4j.gm.internal.Sm2Operations;
import cn.tolim.spissatus4j.gm.sm2.Sm2Cipher;
import cn.tolim.spissatus4j.gm.sm2.Sm2Signature;
import cn.tolim.spissatus4j.gm.sm3.Sm3Hash;
import cn.tolim.spissatus4j.gm.sm3.Sm3Mac;
import cn.tolim.spissatus4j.gm.sm4.Sm4CbcCipher;
import cn.tolim.spissatus4j.gm.sm4.Sm4CtrCipher;
import cn.tolim.spissatus4j.gm.sm4.Sm4GcmCipher;
import cn.tolim.spissatus4j.gm.vector.GmTestVectors;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.BooleanSupplier;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * GM/T algorithm provider: SM2 encryption and signatures, SM3 hashing,
 * HMAC-SM3 and the SM4-GCM/CBC/CTR AEAD surface.
 */
public final class GmAlgorithmProvider implements AlgorithmProvider {

    public static final String PROVIDER_ID = "gm";
    public static final int PRIORITY = 95;

    private static final Set<AlgorithmId> SUPPORTED = Set.of(
            AlgorithmId.SM2,
            AlgorithmId.SM2_SIGNATURE,
            AlgorithmId.SM3,
            AlgorithmId.HMAC_SM3,
            AlgorithmId.SM4_GCM,
            AlgorithmId.SM4_CBC,
            AlgorithmId.SM4_CTR);

    private final Sm2Cipher sm2Cipher = new Sm2Cipher();
    private final Sm2Signature sm2Signature = new Sm2Signature();
    private final Sm3Hash sm3Hash = new Sm3Hash();
    private final Sm3Mac sm3Mac = new Sm3Mac();
    private final Sm4GcmCipher sm4GcmCipher = new Sm4GcmCipher();
    private final Sm4CbcCipher sm4CbcCipher = new Sm4CbcCipher();
    private final Sm4CtrCipher sm4CtrCipher = new Sm4CtrCipher();

    @Override
    public String providerId() {
        return PROVIDER_ID;
    }

    @Override
    public int priority() {
        return PRIORITY;
    }

    @Override
    public Set<AlgorithmId> supportedAlgorithms() {
        return SUPPORTED;
    }

    @Override
    public AeadCipher aeadCipher(AlgorithmId algorithm) {
        requireAlgorithm(algorithm);
        if (AlgorithmId.SM4_GCM.equals(algorithm)) {
            return sm4GcmCipher;
        }
        if (AlgorithmId.SM4_CBC.equals(algorithm)) {
            return sm4CbcCipher;
        }
        if (AlgorithmId.SM4_CTR.equals(algorithm)) {
            return sm4CtrCipher;
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public AsymmetricCipher asymmetricCipher(AlgorithmId algorithm) {
        requireAlgorithm(algorithm);
        if (AlgorithmId.SM2.equals(algorithm)) {
            return sm2Cipher;
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public HashFunction hash(AlgorithmId algorithm) {
        requireAlgorithm(algorithm);
        if (AlgorithmId.SM3.equals(algorithm)) {
            return sm3Hash;
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public MacFunction mac(AlgorithmId algorithm) {
        requireAlgorithm(algorithm);
        if (AlgorithmId.HMAC_SM3.equals(algorithm)) {
            return sm3Mac;
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public SignatureFunction signature(AlgorithmId algorithm) {
        requireAlgorithm(algorithm);
        if (AlgorithmId.SM2_SIGNATURE.equals(algorithm)) {
            return sm2Signature;
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public KdfFunction kdf(AlgorithmId algorithm) {
        requireAlgorithm(algorithm);
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public SelfCheckReport selfCheck() {
        List<SelfCheckResult> checks = new ArrayList<>(6);
        checks.add(runCheck("gm.sm3-abc", GmTestVectors::verifySm3Abc,
                "SM3 ABC known-answer vector"));
        checks.add(runCheck("gm.sm4-ecb-vector", GmTestVectors::verifySm4EcbVector,
                "SM4 ECB known-answer vector"));
        checks.add(runCheck("gm.sm4-gcm-roundtrip", GmTestVectors::verifySm4GcmRoundtrip,
                "SM4-GCM round trip"));
        checks.add(runCheck("gm.sm2-signature", this::sm2SignVerifyRoundtrip,
                "SM2 signature round trip"));
        checks.add(runCheck("gm.sm2-encryption", this::sm2EncryptDecryptRoundtrip,
                "SM2 encryption round trip"));
        checks.add(runCheck("gm.hmac-sm3", this::hmacSm3Consistency,
                "HMAC-SM3 consistency"));
        return SelfCheckReport.of(checks);
    }

    private boolean sm2SignVerifyRoundtrip() {
        AsymmetricCipherKeyPair keyPair = BcKeyConversion.generateKeyPair(new SecureRandom());
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        byte[] message = "spissatus4j-gm-sm2-signature-selfcheck"
                .getBytes(StandardCharsets.US_ASCII);
        byte[] signature = Sm2Operations.sign(privateKey, message, new SecureRandom());
        if (!Sm2Operations.verify(publicKey, message, signature)) {
            return false;
        }
        byte[] tampered = signature.clone();
        tampered[tampered.length - 1] ^= 0x01;
        return !Sm2Operations.verify(publicKey, message, tampered);
    }

    private boolean sm2EncryptDecryptRoundtrip() {
        AsymmetricCipherKeyPair keyPair = BcKeyConversion.generateKeyPair(new SecureRandom());
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        byte[] plaintext = "spissatus4j-gm-sm2-encryption-selfcheck"
                .getBytes(StandardCharsets.US_ASCII);
        byte[] ciphertext = Sm2Operations.encrypt(publicKey, plaintext, new SecureRandom());
        byte[] decrypted = Sm2Operations.decrypt(privateKey, ciphertext);
        return MessageDigest.isEqual(plaintext, decrypted);
    }

    private boolean hmacSm3Consistency() {
        byte[] keyBytes = new byte[Sm3Mac.TAG_LENGTH];
        for (int i = 0; i < keyBytes.length; i++) {
            keyBytes[i] = (byte) (i + 1);
        }
        byte[] data = "spissatus4j-gm-hmac-sm3-selfcheck".getBytes(StandardCharsets.US_ASCII);
        SecretKey key = new SecretKeySpec(keyBytes, "HmacSM3");
        try {
            byte[] first = sm3Mac.compute(key, data);
            byte[] second = sm3Mac.compute(key, data);
            if (!MessageDigest.isEqual(first, second)) {
                return false;
            }
            if (!sm3Mac.verify(key, data, first)) {
                return false;
            }
            byte[] tampered = first.clone();
            tampered[0] ^= 0x01;
            return !sm3Mac.verify(key, data, tampered);
        } finally {
            java.util.Arrays.fill(keyBytes, (byte) 0);
        }
    }

    private static SelfCheckResult runCheck(String checkId, BooleanSupplier check, String description) {
        long started = System.nanoTime();
        boolean passed;
        try {
            passed = check.getAsBoolean();
        } catch (RuntimeException e) {
            passed = false;
        }
        Duration duration = Duration.ofNanos(System.nanoTime() - started);
        String message = passed ? description + " passed" : description + " failed";
        return new SelfCheckResult(checkId,
                passed ? HealthStatus.UP : HealthStatus.DOWN, message, duration);
    }

    private static void requireAlgorithm(AlgorithmId algorithm) {
        if (algorithm == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "Algorithm identifier is required");
        }
    }
}