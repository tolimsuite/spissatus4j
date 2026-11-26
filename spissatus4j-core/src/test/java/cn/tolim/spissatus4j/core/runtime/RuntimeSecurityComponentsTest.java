package cn.tolim.spissatus4j.core.runtime;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.RandomService;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.RuntimeSecurityException;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.RuntimeState;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class RuntimeSecurityComponentsTest {

    private static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-01-01T00:00:00Z");

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }
    }

    @Test
    void detectsNonceReuseAndExpiresEntries() {
        MutableClock clock = new MutableClock();
        BoundedNonceReuseDetector detector = new BoundedNonceReuseDetector(100,
                Duration.ofHours(1), clock);
        Nonce nonce = Nonce.of(new byte[12]);
        assertFalse(detector.register(AlgorithmId.AES_GCM, nonce));
        assertTrue(detector.register(AlgorithmId.AES_GCM, nonce));
        assertEquals(1, detector.size());
        // Same bytes under a different algorithm are not the same nonce use.
        assertFalse(detector.register(AlgorithmId.CHACHA20_POLY1305, nonce));
        clock.advance(Duration.ofHours(2));
        assertFalse(detector.register(AlgorithmId.AES_GCM, nonce));
        assertEquals(HealthStatus.UP, detector.health());
    }

    @Test
    void emptyNonceIsNeverTracked() {
        BoundedNonceReuseDetector detector = new BoundedNonceReuseDetector();
        assertFalse(detector.register(AlgorithmId.AES_GCM, Nonce.empty()));
        assertEquals(0, detector.size());
    }

    @Test
    void failClosedGuardBlocksUnavailableStates() {
        DefaultFailClosedGuard guard = new DefaultFailClosedGuard(RuntimeState.STARTING);
        assertTrue(throwsRuntimeSecurity(guard, "op"));
        guard.transitionTo(RuntimeState.READY);
        guard.ensureOperational("op");
        guard.transitionTo(RuntimeState.DEGRADED);
        guard.ensureOperational("op");
        guard.markUnavailable("test");
        assertEquals(RuntimeState.UNAVAILABLE, guard.state());
        assertTrue(throwsRuntimeSecurity(guard, "op"));
        guard.transitionTo(RuntimeState.READY);
        guard.close();
        assertEquals(RuntimeState.CLOSED, guard.state());
        assertTrue(throwsRuntimeSecurity(guard, "op"));
    }

    private static boolean throwsRuntimeSecurity(DefaultFailClosedGuard guard, String operation) {
        try {
            guard.ensureOperational(operation);
            return false;
        } catch (RuntimeSecurityException e) {
            return true;
        }
    }

    @Test
    void constantTimeComparatorBehavesLikeEquality() {
        DefaultConstantTimeComparator comparator = new DefaultConstantTimeComparator();
        assertTrue(comparator.equals(new byte[]{1, 2, 3}, new byte[]{1, 2, 3}));
        assertFalse(comparator.equals(new byte[]{1, 2, 3}, new byte[]{1, 2, 4}));
        assertFalse(comparator.equals(new byte[]{1, 2}, new byte[]{1, 2, 3}));
        assertTrue(comparator.equals("secret".toCharArray(), "secret".toCharArray()));
        assertFalse(comparator.equals("secret".toCharArray(), "Secret".toCharArray()));
        assertFalse(comparator.equals("secret".toCharArray(), new char[0]));
        assertTrue(comparator.equals((byte[]) null, (byte[]) null));
        assertFalse(comparator.equals(null, new byte[]{1}));
    }

    @Test
    void redactorRemovesSecretsAndPemBlocks() {
        DefaultSensitiveDataRedactor redactor = new DefaultSensitiveDataRedactor();
        String input = "password=hunter2 token: abc123 private_key=xyz "
                + "-----BEGIN PRIVATE KEY-----MIIB-----END PRIVATE KEY-----";
        String output = redactor.redact(input);
        assertFalse(output.contains("hunter2"));
        assertFalse(output.contains("abc123"));
        assertFalse(output.contains("xyz"));
        assertFalse(output.contains("MIIB"));
        assertTrue(output.contains("[REDACTED"));
        String value = redactor.redactValue("master-key", "super-secret");
        assertFalse(value.contains("super-secret"));
        assertTrue(value.contains("len=12"));
        assertNull(redactor.redact(null));
    }

    @Test
    void systemRandomProducesUniqueValuesAndHealthyNonces() {
        SystemRandomService random = new SystemRandomService();
        byte[] first = random.nextBytes(32);
        byte[] second = random.nextBytes(32);
        assertFalse(Arrays.equals(first, second));
        assertEquals(HealthStatus.UP, random.health());
        byte[] nonce = random.nextNonce(AlgorithmId.AES_GCM).asBytes();
        assertEquals(12, nonce.length);
        Salt salt = random.nextSalt(16);
        assertEquals(16, salt.length());
        assertNotEquals(random.nextUuid(), random.nextUuid());
        assertEquals(16, Base64.getDecoder().decode(random.nextBase64(16)).length);
        assertTrue(throwsCrypto(() -> random.nextNonce(AlgorithmId.SHA_256)));
    }

    private static boolean throwsCrypto(Runnable action) {
        try {
            action.run();
            return false;
        } catch (CryptoException e) {
            return true;
        }
    }

    @Test
    void nonceAndSaltAreDefensive() {
        byte[] raw = new byte[]{1, 2, 3};
        Nonce nonce = Nonce.of(raw);
        raw[0] = 99;
        assertArrayEquals(new byte[]{1, 2, 3}, nonce.asBytes());
        byte[] copy = nonce.asBytes();
        copy[1] = 99;
        assertArrayEquals(new byte[]{1, 2, 3}, nonce.asBytes());
        assertFalse(nonce.toString().contains("01"));
    }
}