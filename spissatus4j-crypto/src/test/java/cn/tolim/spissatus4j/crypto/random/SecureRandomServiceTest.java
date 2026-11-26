package cn.tolim.spissatus4j.crypto.random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class SecureRandomServiceTest {

    private static SecureRandomService randomService;

    @BeforeAll
    static void setUp() {
        randomService = new SecureRandomService();
    }

    @Test
    void nextBytesReturnsRequestedLengthAndUniqueData() {
        byte[] value = randomService.nextBytes(128);
        assertEquals(128, value.length);
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            byte[] next = randomService.nextBytes(16);
            assertEquals(16, next.length);
            assertTrue(seen.add(Base64.getEncoder().encodeToString(next)));
        }
        assertEquals(0, randomService.nextBytes(0).length);
    }

    @Test
    void nextBytesRejectsOversizedRequests() {
        assertThrows(IllegalArgumentException.class, () -> randomService.nextBytes(-1));
        assertThrows(IllegalArgumentException.class,
                () -> randomService.nextBytes(1024 * 1024 + 1));
    }

    @Test
    void nextNonceUsesCatalogNonceLengthAndIsUnique() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 200; i++) {
            Nonce nonce = randomService.nextNonce(AlgorithmId.AES_GCM);
            assertEquals(12, nonce.length());
            assertTrue(seen.add(nonce.toString() + Base64.getEncoder().encodeToString(nonce.asBytes())));
        }
        assertEquals(16, randomService.nextNonce(AlgorithmId.AES_CBC).length());
    }

    @Test
    void nextNonceRejectsAlgorithmsWithoutNonce() {
        CryptoException exception = assertThrows(CryptoException.class,
                () -> randomService.nextNonce(AlgorithmId.RSA_OAEP));
        assertEquals(ErrorCode.NONCE_INVALID, exception.errorCode());
        assertThrows(CryptoException.class,
                () -> randomService.nextNonce(AlgorithmId.PBKDF2));
    }

    @Test
    void nextSaltProducesRequestedLength() {
        Salt salt = randomService.nextSalt(32);
        assertEquals(32, salt.length());
        assertNotEquals(Base64.getEncoder().encodeToString(salt.asBytes()),
                Base64.getEncoder().encodeToString(randomService.nextSalt(32).asBytes()));
        assertThrows(IllegalArgumentException.class, () -> randomService.nextSalt(0));
        assertThrows(IllegalArgumentException.class, () -> randomService.nextSalt(257));
    }

    @Test
    void nextUuidIsVersionFour() {
        UUID uuid = randomService.nextUuid();
        assertEquals(4, uuid.version());
        assertEquals(2, uuid.variant());
        assertNotNull(uuid.toString());
    }

    @Test
    void base64AndUrlSafeTokensRoundTrip() {
        String standard = randomService.nextBase64(32);
        assertEquals(32, Base64.getDecoder().decode(standard).length);
        String token = randomService.nextUrlSafeToken(32);
        assertTrue(token.chars().noneMatch(ch -> ch == '+' || ch == '/'));
        assertEquals(32, Base64.getUrlDecoder().decode(token).length);
    }

    @Test
    void healthSelfTestReportsUp() {
        assertEquals(HealthStatus.UP, randomService.health());
        assertTrue(HealthStatus.UP.isUsable());
    }
}
