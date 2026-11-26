package cn.tolim.spissatus4j.core.testkit;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.AsymmetricCipher;
import cn.tolim.spissatus4j.contract.crypto.HashFunction;
import cn.tolim.spissatus4j.contract.crypto.KdfFunction;
import cn.tolim.spissatus4j.contract.crypto.MacFunction;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.SignatureFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckResult;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Minimal JCA provider for core facade tests. Supports AES-GCM and SHA-256
 * only; production algorithms come from the crypto and Bouncy Castle modules.
 */
public final class TestAlgorithmProvider implements AlgorithmProvider {

    private final boolean healthy;

    public TestAlgorithmProvider() {
        this(true);
    }

    public TestAlgorithmProvider(boolean healthy) {
        this.healthy = healthy;
    }

    @Override
    public String providerId() {
        return "test-jca";
    }

    @Override
    public int priority() {
        return 100;
    }

    @Override
    public Set<AlgorithmId> supportedAlgorithms() {
        return Set.of(AlgorithmId.AES_GCM, AlgorithmId.SHA_256);
    }

    @Override
    public AeadCipher aeadCipher(AlgorithmId algorithm) {
        if (algorithm.equals(AlgorithmId.AES_GCM)) {
            return new TestAesGcm();
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public AsymmetricCipher asymmetricCipher(AlgorithmId algorithm) {
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public HashFunction hash(AlgorithmId algorithm) {
        if (algorithm.equals(AlgorithmId.SHA_256)) {
            return new TestSha256();
        }
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public MacFunction mac(AlgorithmId algorithm) {
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public SignatureFunction signature(AlgorithmId algorithm) {
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public KdfFunction kdf(AlgorithmId algorithm) {
        throw CryptoException.unsupported(algorithm);
    }

    @Override
    public SelfCheckReport selfCheck() {
        List<SelfCheckResult> checks = new java.util.ArrayList<>();
        byte[] digest = new TestSha256().digest("abc".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        checks.add(Arrays.equals(digest, TestVectors.SHA256_ABC)
                ? SelfCheckResult.up("test.sha256", "SHA-256 known answer")
                : SelfCheckResult.down("test.sha256", "SHA-256 known answer mismatch"));
        try {
            TestAesGcm cipher = new TestAesGcm();
            SecretKeySpec key = new SecretKeySpec(TestVectors.AES_128_GCM_KEY, "AES");
            byte[] plaintext = "self-check".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            AeadCipher.AeadResult result = cipher.encrypt(key, plaintext,
                    Nonce.of(TestVectors.AES_128_GCM_NONCE), AAD.empty());
            byte[] decrypted = cipher.decrypt(key, result.nonce(), result.ciphertext(),
                    result.tag(), AAD.empty());
            checks.add(Arrays.equals(plaintext, decrypted)
                    ? SelfCheckResult.up("test.aes-gcm", "AES-GCM roundtrip")
                    : SelfCheckResult.down("test.aes-gcm", "AES-GCM roundtrip mismatch"));
        } catch (RuntimeException e) {
            checks.add(SelfCheckResult.down("test.aes-gcm", "AES-GCM self-check failed"));
        }
        if (!healthy) {
            checks.add(SelfCheckResult.down("test.forced", "Forced unhealthy provider"));
        }
        return SelfCheckReport.of(checks);
    }

    private static final class TestAesGcm implements AeadCipher {
        @Override
        public AlgorithmId algorithm() {
            return AlgorithmId.AES_GCM;
        }

        @Override
        public int nonceLength() {
            return 12;
        }

        @Override
        public int tagLength() {
            return 16;
        }

        @Override
        public AeadResult encrypt(javax.crypto.SecretKey key, byte[] plaintext, Nonce nonce, AAD aad) {
            if (nonce.length() != 12) {
                throw new CryptoException(cn.tolim.spissatus4j.contract.exception.ErrorCode.NONCE_INVALID,
                        "AES-GCM requires a 12-byte nonce");
            }
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce.asBytes()));
                if (!aad.isEmpty()) {
                    cipher.updateAAD(aad.asBytes());
                }
                byte[] combined = cipher.doFinal(plaintext);
                int tagOffset = combined.length - 16;
                return new AeadResult(nonce, Arrays.copyOf(combined, tagOffset),
                        Arrays.copyOfRange(combined, tagOffset, combined.length));
            } catch (Exception e) {
                throw new CryptoException(cn.tolim.spissatus4j.contract.exception.ErrorCode.ENCRYPTION_FAILED,
                        "Encryption failed", e);
            }
        }

        @Override
        public byte[] decrypt(javax.crypto.SecretKey key, Nonce nonce, byte[] ciphertext,
                              byte[] tag, AAD aad) {
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce.asBytes()));
                if (!aad.isEmpty()) {
                    cipher.updateAAD(aad.asBytes());
                }
                byte[] combined = new byte[ciphertext.length + tag.length];
                System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
                System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);
                return cipher.doFinal(combined);
            } catch (Exception e) {
                throw CryptoException.authenticationFailed(AlgorithmId.AES_GCM);
            }
        }
    }

    private static final class TestSha256 implements HashFunction {
        @Override
        public AlgorithmId algorithm() {
            return AlgorithmId.SHA_256;
        }

        @Override
        public int digestLength() {
            return 32;
        }

        @Override
        public byte[] digest(byte[] data) {
            try {
                return MessageDigest.getInstance("SHA-256").digest(data);
            } catch (NoSuchAlgorithmException e) {
                throw new CryptoException(cn.tolim.spissatus4j.contract.exception.ErrorCode.PROVIDER_FAILURE,
                        "SHA-256 unavailable", e);
            }
        }

        @Override
        public byte[] digest(InputStream input) throws IOException {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    digest.update(buffer, 0, read);
                }
                return digest.digest();
            } catch (NoSuchAlgorithmException e) {
                throw new CryptoException(cn.tolim.spissatus4j.contract.exception.ErrorCode.PROVIDER_FAILURE,
                        "SHA-256 unavailable", e);
            }
        }
    }
}