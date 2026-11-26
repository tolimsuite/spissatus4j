package cn.tolim.spissatus4j.bc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.bc.provider.BouncyCastleAlgorithmProvider;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.HashFunction;
import cn.tolim.spissatus4j.contract.crypto.MacFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class BouncyCastleAlgorithmProviderTest {

    private static final BouncyCastleAlgorithmProvider PROVIDER = new BouncyCastleAlgorithmProvider();

    @Test
    void providerMetadataIsStable() {
        assertEquals("bouncycastle", PROVIDER.providerId());
        assertEquals(90, PROVIDER.priority());
        assertNotNull(PROVIDER.jcaProvider());
        assertFalse(PROVIDER.fipsCapable());
        assertTrue(new BouncyCastleAlgorithmProvider(PROVIDER.jcaProvider(), true).fipsCapable());
    }

    @Test
    void requiredAlgorithmsAreSupported() {
        Set<AlgorithmId> supported = PROVIDER.supportedAlgorithms();
        for (AlgorithmId algorithm : List.of(
                AlgorithmId.AES_GCM, AlgorithmId.CHACHA20_POLY1305,
                AlgorithmId.SHA3_256, AlgorithmId.SHA3_512,
                AlgorithmId.SHAKE_128, AlgorithmId.SHAKE_256,
                AlgorithmId.BLAKE2B_256, AlgorithmId.BLAKE2B_512,
                AlgorithmId.ARGON2ID, AlgorithmId.SCRYPT, AlgorithmId.PBKDF2, AlgorithmId.HKDF,
                AlgorithmId.ED448, AlgorithmId.RSA_PSS, AlgorithmId.ECDSA_P256,
                AlgorithmId.ECDSA_P384, AlgorithmId.RSA_OAEP, AlgorithmId.BCRYPT,
                AlgorithmId.ECIES, AlgorithmId.CMAC_AES,
                AlgorithmId.RSA_PKCS1_SIGNATURE)) {
            assertTrue(supported.contains(algorithm), "missing support for " + algorithm);
            assertTrue(PROVIDER.supports(algorithm));
        }
        for (AlgorithmId algorithm : List.of(AlgorithmId.AES_CBC, AlgorithmId.SM4_GCM,
                AlgorithmId.SHA_1, AlgorithmId.MD5, AlgorithmId.ED25519, AlgorithmId.SM2,
                AlgorithmId.ML_KEM_768, AlgorithmId.HMAC_SM3,
                AlgorithmId.RSA_PKCS1, AlgorithmId.ML_DSA_65)) {
            assertFalse(supported.contains(algorithm), "unexpected support for " + algorithm);
            assertFalse(PROVIDER.supports(algorithm));
        }
    }

    @Test
    void engineMetadataMatchesContract() {
        AeadCipher aes = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        assertEquals(AlgorithmId.AES_GCM, aes.algorithm());
        assertEquals(12, aes.nonceLength());
        assertEquals(16, aes.tagLength());

        AeadCipher chacha = PROVIDER.aeadCipher(AlgorithmId.CHACHA20_POLY1305);
        assertEquals(12, chacha.nonceLength());
        assertEquals(16, chacha.tagLength());

        assertDigestLength(AlgorithmId.SHA_256, 32);
        assertDigestLength(AlgorithmId.SHA_384, 48);
        assertDigestLength(AlgorithmId.SHA_512, 64);
        assertDigestLength(AlgorithmId.SHA3_256, 32);
        assertDigestLength(AlgorithmId.SHA3_512, 64);
        assertDigestLength(AlgorithmId.SHAKE_128, 32);
        assertDigestLength(AlgorithmId.SHAKE_256, 64);
        assertDigestLength(AlgorithmId.BLAKE2B_256, 32);
        assertDigestLength(AlgorithmId.BLAKE2B_512, 64);

        assertMacLength(AlgorithmId.HMAC_SHA256, 32);
        assertMacLength(AlgorithmId.HMAC_SHA384, 48);
        assertMacLength(AlgorithmId.HMAC_SHA512, 64);
        assertMacLength(AlgorithmId.CMAC_AES, 16);

        assertEquals(AlgorithmId.RSA_OAEP,
                PROVIDER.asymmetricCipher(AlgorithmId.RSA_OAEP).algorithm());
        assertEquals(AlgorithmId.ECIES,
                PROVIDER.asymmetricCipher(AlgorithmId.ECIES).algorithm());
        assertEquals(AlgorithmId.RSA_PKCS1_SIGNATURE,
                PROVIDER.signature(AlgorithmId.RSA_PKCS1_SIGNATURE).algorithm());
    }

    @Test
    void fipsModeOnlyExposesApprovedAlgorithms() {
        BouncyCastleAlgorithmProvider fips =
                new BouncyCastleAlgorithmProvider(PROVIDER.jcaProvider(), true);
        assertTrue(fips.supports(AlgorithmId.AES_GCM));
        assertTrue(fips.supports(AlgorithmId.SHA3_256));
        assertTrue(fips.supports(AlgorithmId.PBKDF2));
        assertTrue(fips.supports(AlgorithmId.RSA_PSS));
        assertTrue(fips.supports(AlgorithmId.CMAC_AES));
        assertTrue(fips.supports(AlgorithmId.RSA_PKCS1_SIGNATURE));
        assertTrue(fips.supports(AlgorithmId.HKDF));
        assertFalse(fips.supports(AlgorithmId.CHACHA20_POLY1305));
        assertFalse(fips.supports(AlgorithmId.BLAKE2B_512));
        assertFalse(fips.supports(AlgorithmId.ARGON2ID));
        assertFalse(fips.supports(AlgorithmId.ED448));
        assertFalse(fips.supports(AlgorithmId.BCRYPT));
        assertFalse(fips.supports(AlgorithmId.ECIES));
        assertThrows(CryptoException.class, () -> fips.aeadCipher(AlgorithmId.CHACHA20_POLY1305));
        assertThrows(CryptoException.class, () -> fips.asymmetricCipher(AlgorithmId.ECIES));
    }

    @Test
    void unsupportedEnginesFailClosed() {
        assertUnsupported(() -> PROVIDER.aeadCipher(AlgorithmId.AES_CBC));
        assertUnsupported(() -> PROVIDER.hash(AlgorithmId.SHA_1));
        assertUnsupported(() -> PROVIDER.mac(AlgorithmId.HMAC_SM3));
        assertUnsupported(() -> PROVIDER.signature(AlgorithmId.ED25519));
        assertUnsupported(() -> PROVIDER.kdf(AlgorithmId.CMAC_AES));
        assertUnsupported(() -> PROVIDER.asymmetricCipher(AlgorithmId.RSA_PKCS1));
    }

    @Test
    void selfCheckIsUpAndReportsKnownAnswers() {
        SelfCheckReport report = PROVIDER.selfCheck();

        assertEquals(HealthStatus.UP, report.overall());
        assertTrue(report.passed());
        assertTrue(report.failures().isEmpty());
        List<String> checkIds = report.checks().stream().map(check -> check.checkId()).toList();
        assertTrue(checkIds.containsAll(List.of(
                "bc.hash.sha3-256", "bc.hash.sha-256", "bc.hash.blake2b-512",
                "bc.aead.aes-gcm", "bc.mac.cmac-aes", "bc.asymmetric.ecies",
                "bc.signature.rsa-pkcs1", "bc.kdf.argon2id", "bc.kdf.scrypt",
                "bc.interop.aes-gcm", "bc.interop.digest", "bc.interop.signature")));
        assertTrue(report.checks().stream().noneMatch(check ->
                check.message().toLowerCase().contains("password")));
    }

    @Test
    void closeIsIdempotent() {
        PROVIDER.close();
        PROVIDER.close();
    }

    private static void assertDigestLength(AlgorithmId algorithm, int expected) {
        HashFunction hash = PROVIDER.hash(algorithm);
        assertEquals(algorithm, hash.algorithm());
        assertEquals(expected, hash.digestLength());
    }

    private static void assertMacLength(AlgorithmId algorithm, int expected) {
        MacFunction mac = PROVIDER.mac(algorithm);
        assertEquals(algorithm, mac.algorithm());
        assertEquals(expected, mac.tagLength());
    }

    private static void assertUnsupported(org.junit.jupiter.api.function.Executable call) {
        CryptoException failure = assertThrows(CryptoException.class, call);
        assertEquals(ErrorCode.ALGORITHM_UNSUPPORTED, failure.errorCode());
    }
}