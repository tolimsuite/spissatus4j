package cn.tolim.spissatus4j.crypto.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.MacFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.crypto.TestSupport;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class JcaAlgorithmProviderTest {

    private static JcaAlgorithmProvider provider;

    @BeforeAll
    static void setUp() {
        provider = new JcaAlgorithmProvider();
    }

    @Test
    void exposesRequiredAlgorithmCatalog() {
        assertEquals("jca", provider.providerId());
        assertEquals(100, provider.priority());
        assertTrue(provider.supportedAlgorithms().containsAll(Set.of(
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
                AlgorithmId.HKDF)));
        assertTrue(provider.supports(AlgorithmId.AES_GCM));
        assertFalse(provider.supports(AlgorithmId.AES_ECB));
    }

    @Test
    void hashKnownAnswerVectors() {
        assertArrayEquals(TestSupport.hex(
                        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                provider.hash(AlgorithmId.SHA_256).digest("abc".getBytes(StandardCharsets.US_ASCII)));
        assertArrayEquals(TestSupport.hex(
                        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                                + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
                provider.hash(AlgorithmId.SHA_512).digest("abc".getBytes(StandardCharsets.US_ASCII)));
        assertArrayEquals(TestSupport.hex(
                        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
                provider.hash(AlgorithmId.SHA3_256).digest("abc".getBytes(StandardCharsets.US_ASCII)));
        assertEquals(32, provider.hash(AlgorithmId.SHA_256).digestLength());
        assertEquals(64, provider.hash(AlgorithmId.SHA3_512).digestLength());
    }

    @Test
    void streamingHashMatchesOneShot() throws IOException {
        byte[] data = TestSupport.bytes(100_000, 77);
        byte[] oneShot = provider.hash(AlgorithmId.SHA_384).digest(data);
        byte[] streamed = provider.hash(AlgorithmId.SHA_384)
                .digest(new ByteArrayInputStream(data));
        assertArrayEquals(oneShot, streamed);
    }

    @Test
    void hmacRfc4231CaseOne() {
        byte[] keyBytes = new byte[20];
        java.util.Arrays.fill(keyBytes, (byte) 0x0b);
        SecretKey key = new SecretKeySpec(keyBytes, "HmacSHA256");
        MacFunction mac = provider.mac(AlgorithmId.HMAC_SHA256);
        byte[] tag = mac.compute(key, "Hi There".getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(TestSupport.hex(
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"), tag);
        assertEquals(32, tag.length);
        assertTrue(mac.verify(key, "Hi There".getBytes(StandardCharsets.US_ASCII), tag));
        assertFalse(mac.verify(key, "Hi There!".getBytes(StandardCharsets.US_ASCII), tag));
    }

    @Test
    void streamingMacMatchesOneShot() throws IOException {
        SecretKey key = new SecretKeySpec(TestSupport.bytes(32, 5), "HmacSHA512");
        MacFunction mac = provider.mac(AlgorithmId.HMAC_SHA512);
        byte[] data = TestSupport.bytes(70_000, 6);
        assertArrayEquals(mac.compute(key, data), mac.compute(key, new ByteArrayInputStream(data)));
    }

    @Test
    void selfCheckPassesKnownAnswerTests() {
        SelfCheckReport report = provider.selfCheck();
        assertEquals(HealthStatus.UP, report.overall(), () -> report.failures().toString());
        assertTrue(report.passed());
        assertTrue(report.checks().stream().anyMatch(c -> c.checkId().equals("sha256-abc")));
        assertTrue(report.checks().stream().anyMatch(c -> c.checkId().equals("aes-128-gcm-empty")));
        assertTrue(report.checks().stream().anyMatch(c -> c.checkId().equals("hkdf-sha256-rfc5869-1")));
    }

    @Test
    void unsupportedAlgorithmsAreRejected() {
        assertUnsupported(() -> provider.aeadCipher(AlgorithmId.SHA_256));
        assertUnsupported(() -> provider.asymmetricCipher(AlgorithmId.ED25519));
        assertUnsupported(() -> provider.hash(AlgorithmId.AES_GCM));
        assertUnsupported(() -> provider.mac(AlgorithmId.SHA_256));
        assertUnsupported(() -> provider.signature(AlgorithmId.SHA_256));
        assertUnsupported(() -> provider.kdf(AlgorithmId.SCRYPT));
    }

    @Test
    void blockModesAreOnlyExposedAsEncryptThenMac() {
        for (AlgorithmId algorithm : Set.of(AlgorithmId.AES_CBC, AlgorithmId.AES_CTR,
                AlgorithmId.AES_CFB, AlgorithmId.AES_OFB)) {
            AeadCipher cipher = provider.aeadCipher(algorithm);
            assertEquals(16, cipher.nonceLength());
            assertEquals(32, cipher.tagLength());
            assertEquals(algorithm, cipher.algorithm());
        }
    }

    private static void assertUnsupported(org.junit.jupiter.api.function.Executable executable) {
        CryptoException exception = assertThrows(CryptoException.class, executable);
        assertEquals(ErrorCode.ALGORITHM_UNSUPPORTED, exception.errorCode());
    }
}
