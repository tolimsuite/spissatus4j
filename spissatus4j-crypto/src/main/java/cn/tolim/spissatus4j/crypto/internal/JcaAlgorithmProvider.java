package cn.tolim.spissatus4j.crypto.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.contract.crypto.HashFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.crypto.MacFunction;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.crypto.SignatureFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckResult;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Default algorithm provider backed exclusively by the JDK JCA/JCE providers.
 * Every engine is a thin standard-construction wrapper; no primitives are
 * implemented here.
 */
public final class JcaAlgorithmProvider implements AlgorithmProvider {

    public static final String PROVIDER_ID = "jca";
    public static final int PRIORITY = 100;

    private static final Set<AlgorithmId> SUPPORTED = Set.of(
            AlgorithmId.AES_GCM,
            AlgorithmId.AES_CBC,
            AlgorithmId.AES_CTR,
            AlgorithmId.AES_CFB,
            AlgorithmId.AES_OFB,
            AlgorithmId.CHACHA20_POLY1305,
            AlgorithmId.RSA_OAEP,
            AlgorithmId.RSA_PKCS1,
            AlgorithmId.ECDSA_P256,
            AlgorithmId.ECDSA_P384,
            AlgorithmId.ED25519,
            AlgorithmId.ED448,
            AlgorithmId.RSA_PSS,
            AlgorithmId.SHA_256,
            AlgorithmId.SHA_384,
            AlgorithmId.SHA_512,
            AlgorithmId.SHA3_256,
            AlgorithmId.SHA3_512,
            AlgorithmId.HMAC_SHA256,
            AlgorithmId.HMAC_SHA384,
            AlgorithmId.HMAC_SHA512,
            AlgorithmId.PBKDF2,
            AlgorithmId.HKDF);

    private static final Map<AlgorithmId, String> HASHES = Map.of(
            AlgorithmId.SHA_256, "SHA-256",
            AlgorithmId.SHA_384, "SHA-384",
            AlgorithmId.SHA_512, "SHA-512",
            AlgorithmId.SHA3_256, "SHA3-256",
            AlgorithmId.SHA3_512, "SHA3-512");

    private static final Map<AlgorithmId, String> MACS = Map.of(
            AlgorithmId.HMAC_SHA256, "HmacSHA256",
            AlgorithmId.HMAC_SHA384, "HmacSHA384",
            AlgorithmId.HMAC_SHA512, "HmacSHA512");

    private static final PSSParameterSpec RSA_PSS_PARAMETERS =
            new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

    private final Map<AlgorithmId, AeadCipher> aeadCiphers = Map.of(
            AlgorithmId.AES_GCM, new AesGcmCipher(),
            AlgorithmId.CHACHA20_POLY1305, new ChaCha20Poly1305Cipher(),
            AlgorithmId.AES_CBC, new EtmAeadCipher(AlgorithmId.AES_CBC, "AES/CBC/PKCS5Padding"),
            AlgorithmId.AES_CTR, new EtmAeadCipher(AlgorithmId.AES_CTR, "AES/CTR/NoPadding"),
            AlgorithmId.AES_CFB, new EtmAeadCipher(AlgorithmId.AES_CFB, "AES/CFB/NoPadding"),
            AlgorithmId.AES_OFB, new EtmAeadCipher(AlgorithmId.AES_OFB, "AES/OFB/NoPadding"));

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
        Objects.requireNonNull(algorithm, "algorithm");
        AeadCipher cipher = aeadCiphers.get(algorithm);
        if (cipher == null) {
            throw CryptoException.unsupported(algorithm);
        }
        return cipher;
    }

    @Override
    public AsymmetricCipher asymmetricCipher(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        if (AlgorithmId.RSA_OAEP.equals(algorithm)) {
            return JcaAsymmetricCipher.rsaOaep();
        }
        if (AlgorithmId.RSA_PKCS1.equals(algorithm)) {
            return JcaAsymmetricCipher.rsaPkcs1();
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public HashFunction hash(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        String jcaName = HASHES.get(algorithm);
        if (jcaName == null) {
            throw CryptoException.unsupported(algorithm);
        }
        return new JcaHashFunction(algorithm, jcaName);
    }

    @Override
    public MacFunction mac(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        String jcaName = MACS.get(algorithm);
        if (jcaName == null) {
            throw CryptoException.unsupported(algorithm);
        }
        return new JcaMacFunction(algorithm, jcaName);
    }

    @Override
    public SignatureFunction signature(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        if (AlgorithmId.ED25519.equals(algorithm)) {
            return new JcaSignatureFunction(algorithm, "Ed25519", null);
        }
        if (AlgorithmId.ED448.equals(algorithm)) {
            return new JcaSignatureFunction(algorithm, "Ed448", null);
        }
        if (AlgorithmId.ECDSA_P256.equals(algorithm)) {
            return new JcaSignatureFunction(algorithm, "SHA256withECDSAinP1363Format", null);
        }
        if (AlgorithmId.ECDSA_P384.equals(algorithm)) {
            return new JcaSignatureFunction(algorithm, "SHA384withECDSAinP1363Format", null);
        }
        if (AlgorithmId.RSA_PSS.equals(algorithm)) {
            return new JcaSignatureFunction(algorithm, "RSASSA-PSS", RSA_PSS_PARAMETERS);
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public KdfFunction kdf(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        if (AlgorithmId.PBKDF2.equals(algorithm)) {
            return new Pbkdf2Function();
        }
        if (AlgorithmId.HKDF.equals(algorithm)) {
            return new HkdfFunction();
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public SelfCheckReport selfCheck() {
        List<SelfCheckResult> results = new ArrayList<>();
        results.add(check("sha256-abc", () -> {
            byte[] expected = CryptoSupport.hex(
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
            requireEqual(expected, hash(AlgorithmId.SHA_256).digest(
                    "abc".getBytes(StandardCharsets.US_ASCII)));
        }));
        results.add(check("aes-128-gcm-empty", () -> {
            SecretKey key = new SecretKeySpec(new byte[16], "AES");
            AeadCipher.AeadResult result = aeadCipher(AlgorithmId.AES_GCM).encrypt(
                    key, new byte[0], Nonce.of(new byte[12]), AAD.empty());
            requireEqual(CryptoSupport.hex("58e2fccefa7e3061367f1d57a4e7455a"), result.tag());
            requireEqual(new byte[0], result.ciphertext());
        }));
        results.add(check("hmac-sha256-rfc4231-1", () -> {
            byte[] keyBytes = new byte[20];
            Arrays.fill(keyBytes, (byte) 0x0b);
            byte[] tag = mac(AlgorithmId.HMAC_SHA256).compute(
                    new SecretKeySpec(keyBytes, "HmacSHA256"),
                    "Hi There".getBytes(StandardCharsets.US_ASCII));
            requireEqual(CryptoSupport.hex(
                    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"), tag);
        }));
        results.add(check("hkdf-sha256-rfc5869-1", () -> {
            byte[] ikm = new byte[22];
            Arrays.fill(ikm, (byte) 0x0b);
            byte[] salt = CryptoSupport.hex("000102030405060708090a0b0c");
            byte[] info = CryptoSupport.hex("f0f1f2f3f4f5f6f7f8f9");
            byte[] expected = CryptoSupport.hex(
                    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                            + "34007208d5b887185865");
            byte[] derived = kdf(AlgorithmId.HKDF).derive(ikm, null, Salt.of(salt),
                    new KdfParameters.Hkdf(42, info, "HmacSHA256"));
            requireEqual(expected, derived);
        }));
        results.add(check("aes-gcm-roundtrip", () -> {
            SecretKey key = new SecretKeySpec(fixedBytes(32, 1), "AES");
            Nonce nonce = Nonce.of(fixedBytes(12, 2));
            byte[] plaintext = fixedBytes(257, 3);
            AAD aad = AAD.ofUtf8("self-check");
            AeadCipher cipher = aeadCipher(AlgorithmId.AES_GCM);
            AeadCipher.AeadResult encrypted = cipher.encrypt(key, plaintext, nonce, aad);
            byte[] decrypted = cipher.decrypt(key, nonce, encrypted.ciphertext(),
                    encrypted.tag(), aad);
            requireEqual(plaintext, decrypted);
        }));
        results.add(check("chacha20-poly1305-roundtrip", () -> {
            SecretKey key = new SecretKeySpec(fixedBytes(32, 4), "ChaCha20");
            Nonce nonce = Nonce.of(fixedBytes(12, 5));
            byte[] plaintext = fixedBytes(311, 6);
            AAD aad = AAD.ofUtf8("self-check");
            AeadCipher cipher = aeadCipher(AlgorithmId.CHACHA20_POLY1305);
            AeadCipher.AeadResult encrypted = cipher.encrypt(key, plaintext, nonce, aad);
            byte[] decrypted = cipher.decrypt(key, nonce, encrypted.ciphertext(),
                    encrypted.tag(), aad);
            requireEqual(plaintext, decrypted);
        }));
        results.add(check("etm-aes-cbc-roundtrip", () -> {
            SecretKey key = new SecretKeySpec(fixedBytes(16, 7), "AES");
            Nonce nonce = Nonce.of(fixedBytes(16, 8));
            byte[] plaintext = fixedBytes(123, 9);
            AAD aad = AAD.ofUtf8("self-check");
            AeadCipher cipher = aeadCipher(AlgorithmId.AES_CBC);
            AeadCipher.AeadResult encrypted = cipher.encrypt(key, plaintext, nonce, aad);
            byte[] decrypted = cipher.decrypt(key, nonce, encrypted.ciphertext(),
                    encrypted.tag(), aad);
            requireEqual(plaintext, decrypted);
        }));
        return SelfCheckReport.of(results);
    }

    private static SelfCheckResult check(String checkId, Runnable body) {
        try {
            body.run();
            return SelfCheckResult.up(checkId, "ok");
        } catch (Throwable failure) {
            return SelfCheckResult.down(checkId, "Known-answer self-check failed");
        }
    }

    private static void requireEqual(byte[] expected, byte[] actual) {
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new IllegalStateException("Self-check mismatch");
        }
    }

    private static byte[] fixedBytes(int length, int seed) {
        byte[] value = new byte[length];
        for (int i = 0; i < length; i++) {
            value[i] = (byte) (seed + i * 31);
        }
        return value;
    }
}
