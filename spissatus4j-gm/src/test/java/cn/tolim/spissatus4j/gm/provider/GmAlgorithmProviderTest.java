package cn.tolim.spissatus4j.gm.provider;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckResult;
import cn.tolim.spissatus4j.gm.sm2.Sm2Cipher;
import cn.tolim.spissatus4j.gm.sm2.Sm2Signature;
import cn.tolim.spissatus4j.gm.sm3.Sm3Hash;
import cn.tolim.spissatus4j.gm.sm3.Sm3Mac;
import cn.tolim.spissatus4j.gm.sm4.Sm4CbcCipher;
import cn.tolim.spissatus4j.gm.sm4.Sm4CtrCipher;
import cn.tolim.spissatus4j.gm.sm4.Sm4GcmCipher;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GmAlgorithmProviderTest {

    private final GmAlgorithmProvider provider = new GmAlgorithmProvider();

    @Test
    void metadata() {
        assertEquals("gm", provider.providerId());
        assertEquals(95, provider.priority());
        assertEquals(Set.of(AlgorithmId.SM2, AlgorithmId.SM2_SIGNATURE, AlgorithmId.SM3,
                AlgorithmId.HMAC_SM3, AlgorithmId.SM4_GCM, AlgorithmId.SM4_CBC,
                AlgorithmId.SM4_CTR), provider.supportedAlgorithms());
        assertTrue(provider.supports(AlgorithmId.SM3));
        assertFalse(provider.supports(AlgorithmId.AES_GCM));
    }

    @Test
    void aeadCipherFactoryReturnsMatchingEngines() {
        assertInstanceOf(Sm4GcmCipher.class, provider.aeadCipher(AlgorithmId.SM4_GCM));
        assertInstanceOf(Sm4CbcCipher.class, provider.aeadCipher(AlgorithmId.SM4_CBC));
        assertInstanceOf(Sm4CtrCipher.class, provider.aeadCipher(AlgorithmId.SM4_CTR));
        assertEquals(AlgorithmId.SM4_GCM, provider.aeadCipher(AlgorithmId.SM4_GCM).algorithm());
        assertEquals(AlgorithmId.SM4_CBC, provider.aeadCipher(AlgorithmId.SM4_CBC).algorithm());
        assertEquals(AlgorithmId.SM4_CTR, provider.aeadCipher(AlgorithmId.SM4_CTR).algorithm());
    }

    @Test
    void asymmetricCipherFactory() {
        assertInstanceOf(Sm2Cipher.class, provider.asymmetricCipher(AlgorithmId.SM2));
        assertEquals(AlgorithmId.SM2, provider.asymmetricCipher(AlgorithmId.SM2).algorithm());
    }

    @Test
    void hashMacAndSignatureFactories() {
        assertInstanceOf(Sm3Hash.class, provider.hash(AlgorithmId.SM3));
        assertInstanceOf(Sm3Mac.class, provider.mac(AlgorithmId.HMAC_SM3));
        assertInstanceOf(Sm2Signature.class, provider.signature(AlgorithmId.SM2_SIGNATURE));
        assertEquals(AlgorithmId.SM3, provider.hash(AlgorithmId.SM3).algorithm());
        assertEquals(AlgorithmId.HMAC_SM3, provider.mac(AlgorithmId.HMAC_SM3).algorithm());
        assertEquals(AlgorithmId.SM2_SIGNATURE,
                provider.signature(AlgorithmId.SM2_SIGNATURE).algorithm());
    }

    @Test
    void unsupportedAlgorithmsAreRejected() {
        assertUnsupported(() -> provider.aeadCipher(AlgorithmId.AES_GCM));
        assertUnsupported(() -> provider.asymmetricCipher(AlgorithmId.RSA_OAEP));
        assertUnsupported(() -> provider.hash(AlgorithmId.SHA_256));
        assertUnsupported(() -> provider.mac(AlgorithmId.HMAC_SHA256));
        assertUnsupported(() -> provider.signature(AlgorithmId.ED25519));
        assertUnsupported(() -> provider.kdf(AlgorithmId.HKDF));
    }

    @Test
    void nullAlgorithmIsRejected() {
        CryptoException exception =
                assertThrows(CryptoException.class, () -> provider.aeadCipher(null));
        assertEquals(ErrorCode.INVALID_PARAMETER, exception.errorCode());
    }

    @Test
    void selfCheckIsUp() {
        SelfCheckReport report = provider.selfCheck();
        assertEquals(HealthStatus.UP, report.overall());
        assertTrue(report.passed());
        assertEquals(6, report.checks().size());
        assertTrue(report.failures().isEmpty());
        assertFalse(report.duration().isNegative());
        for (SelfCheckResult check : report.checks()) {
            assertEquals(HealthStatus.UP, check.status());
            assertFalse(check.checkId().isBlank());
            assertFalse(check.message().isBlank());
            assertFalse(check.duration().isNegative());
        }
        assertTrue(report.checks().stream()
                .anyMatch(check -> check.checkId().contains("sm3")));
        assertTrue(report.checks().stream()
                .anyMatch(check -> check.checkId().contains("sm2")));
    }

    @Test
    void selfCheckIsRepeatable() {
        assertTrue(provider.selfCheck().passed());
        assertTrue(provider.selfCheck().passed());
    }

    private static void assertUnsupported(org.junit.jupiter.api.function.Executable executable) {
        CryptoException exception = assertThrows(CryptoException.class, executable);
        assertEquals(ErrorCode.ALGORITHM_UNSUPPORTED, exception.errorCode());
    }
}