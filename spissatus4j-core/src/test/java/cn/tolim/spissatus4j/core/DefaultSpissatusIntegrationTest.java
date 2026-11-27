package cn.tolim.spissatus4j.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.facade.Spissatus;
import cn.tolim.spissatus4j.contract.audit.AuditEventType;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.DecryptRequest;
import cn.tolim.spissatus4j.contract.crypto.DigestRequest;
import cn.tolim.spissatus4j.contract.crypto.EncryptRequest;
import cn.tolim.spissatus4j.contract.crypto.EncryptedData;
import cn.tolim.spissatus4j.contract.exception.AuditException;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.PolicyException;
import cn.tolim.spissatus4j.contract.exception.RuntimeSecurityException;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.NonceReuseDetector;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.core.builder.SpissatusBuilders;
import cn.tolim.spissatus4j.core.testkit.TestAlgorithmProvider;
import cn.tolim.spissatus4j.core.testkit.TestVectors;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import org.junit.jupiter.api.Test;

class DefaultSpissatusIntegrationTest {

    private static final CallerContext CALLER =
            CallerContext.of("tester", TestKeyManager.TENANT, Set.of("crypto-user"));

    private Spissatus facade() {
        return SpissatusBuilders.builder()
                .discoverModules(false)
                .algorithmProvider(new TestAlgorithmProvider())
                .keyManager(new TestKeyManager())
                .build();
    }

    private EncryptRequest encryptRequest(byte[] plaintext, AAD aad) {
        return EncryptRequest.builder(AlgorithmId.AES_GCM, TestKeyManager.KEY_ID, plaintext, CALLER)
                .aad(aad)
                .build();
    }

    @Test
    void encryptsAndDecryptsThroughTheFacade() {
        try (Spissatus facade = facade()) {
            assertEquals(HealthStatus.UP, facade.health());
            assertTrue(facade.capabilities().supports(AlgorithmId.AES_GCM));
            byte[] plaintext = "hello spissatus".getBytes(StandardCharsets.UTF_8);
            EncryptedData data = facade.crypto().encrypt(encryptRequest(plaintext, AAD.empty()));
            assertTrue(data.ciphertext().length > 0);
            assertEquals(16, data.tag().length);
            assertEquals(12, data.nonce().length());
            byte[] decrypted = facade.crypto().decrypt(DecryptRequest.from(data, CALLER));
            assertArrayEquals(plaintext, decrypted);
            assertTrue(facade.auditTrail().recent(20).stream()
                    .anyMatch(e -> e.type() == AuditEventType.ENCRYPT));
            assertTrue(facade.auditTrail().recent(20).stream()
                    .anyMatch(e -> e.type() == AuditEventType.DECRYPT));
            var chainStatus = facade.auditTrail().verify();
            assertTrue(chainStatus.intact(), () -> "audit chain broken: " + chainStatus.failureReason());
        }
    }

    @Test
    void rejectsTamperedTagAndMismatchedAad() {
        try (Spissatus facade = facade()) {
            byte[] plaintext = "authenticated".getBytes(StandardCharsets.UTF_8);
            EncryptedData data = facade.crypto().encrypt(encryptRequest(plaintext,
                    AAD.ofUtf8("context")));
            byte[] badTag = data.tag().clone();
            badTag[0] ^= 0x01;
            DecryptRequest tampered = DecryptRequest.builder(data.algorithm(), data.keyId(),
                            data.ciphertext(), CALLER)
                    .keyVersion(data.keyVersion()).nonce(data.nonce()).tag(badTag)
                    .aad(data.aad()).build();
            CryptoException failure = assertThrows(CryptoException.class,
                    () -> facade.crypto().decrypt(tampered));
            assertEquals(cn.tolim.spissatus4j.contract.exception.ErrorCode.AUTHENTICATION_FAILED,
                    failure.errorCode());
            DecryptRequest wrongAad = DecryptRequest.from(data, CALLER).toBuilder()
                    .aad(AAD.ofUtf8("other")).build();
            assertThrows(CryptoException.class, () -> facade.crypto().decrypt(wrongAad));
        }
    }

    @Test
    void deniesAnonymousCallers() {
        try (Spissatus facade = facade()) {
            EncryptRequest request = EncryptRequest.builder(AlgorithmId.AES_GCM,
                            TestKeyManager.KEY_ID, new byte[]{1}, CallerContext.anonymous())
                    .build();
            PolicyException failure = assertThrows(PolicyException.class,
                    () -> facade.crypto().encrypt(request));
            assertEquals(cn.tolim.spissatus4j.contract.exception.ErrorCode.ACCESS_DENIED,
                    failure.errorCode());
        }
    }

    @Test
    void deniesProhibitedDigestAlgorithms() {
        try (Spissatus facade = facade()) {
            PolicyException failure = assertThrows(PolicyException.class,
                    () -> facade.crypto().digest(new DigestRequest(AlgorithmId.MD5,
                            new byte[]{1}, CALLER)));
            assertEquals(cn.tolim.spissatus4j.contract.exception.ErrorCode.ALGORITHM_PROHIBITED,
                    failure.errorCode());
        }
    }

    @Test
    void digestMatchesKnownVector() {
        try (Spissatus facade = facade()) {
            byte[] digest = facade.crypto().digest(new DigestRequest(AlgorithmId.SHA_256,
                    "abc".getBytes(StandardCharsets.UTF_8), CALLER));
            assertArrayEquals(TestVectors.SHA256_ABC, digest);
        }
    }

    @Test
    void failedSelfCheckBlocksStartupByDefault() {
        ConfigurationException failure = assertThrows(ConfigurationException.class,
                () -> SpissatusBuilders.builder()
                        .discoverModules(false)
                        .algorithmProvider(new TestAlgorithmProvider(false))
                        .keyManager(new TestKeyManager())
                        .build());
        assertEquals(cn.tolim.spissatus4j.contract.exception.ErrorCode.SELF_CHECK_FAILED,
                failure.errorCode());
    }

    @Test
    void failedSelfCheckCanMarkRuntimeUnavailable() {
        try (Spissatus facade = SpissatusBuilders.builder()
                .discoverModules(false)
                .algorithmProvider(new TestAlgorithmProvider(false))
                .keyManager(new TestKeyManager())
                .selfCheckFailureFailsStartup(false)
                .build()) {
            assertEquals(cn.tolim.spissatus4j.contract.runtime.RuntimeState.UNAVAILABLE,
                    facade.state());
            assertEquals(HealthStatus.DOWN, facade.health());
            assertThrows(RuntimeSecurityException.class,
                    () -> facade.crypto().randomBytes(8));
        }
    }

    @Test
    void missingProviderFailsAssembly() {
        assertThrows(ConfigurationException.class, () -> SpissatusBuilders.builder()
                .discoverModules(false)
                .keyManager(new TestKeyManager())
                .build());
    }

    @Test
    void nonceReuseIsFailClosed() {
        NonceReuseDetector alwaysReused = new NonceReuseDetector() {
            @Override
            public boolean register(AlgorithmId algorithm, Nonce nonce) {
                return true;
            }

            @Override
            public void clear() {
            }

            @Override
            public HealthStatus health() {
                return HealthStatus.UP;
            }

            @Override
            public int size() {
                return 0;
            }
        };
        try (Spissatus facade = SpissatusBuilders.builder()
                .discoverModules(false)
                .algorithmProvider(new TestAlgorithmProvider())
                .keyManager(new TestKeyManager())
                .nonceReuseDetector(alwaysReused)
                .build()) {
            RuntimeSecurityException failure = assertThrows(RuntimeSecurityException.class,
                    () -> facade.crypto().encrypt(encryptRequest(new byte[]{1}, AAD.empty())));
            assertEquals(cn.tolim.spissatus4j.contract.exception.ErrorCode.NONCE_REUSE,
                    failure.errorCode());
        }
    }

    @Test
    void auditFailureCanFailOperations() {
        var throwingTrail = new cn.tolim.spissatus4j.contract.audit.AuditTrail() {
            @Override
            public cn.tolim.spissatus4j.contract.audit.AuditEvent append(
                    cn.tolim.spissatus4j.contract.audit.AuditEvent event) {
                throw new AuditException(cn.tolim.spissatus4j.contract.exception.ErrorCode.AUDIT_FAILURE,
                        "down");
            }

            @Override
            public cn.tolim.spissatus4j.contract.audit.AuditChainStatus verify() {
                return cn.tolim.spissatus4j.contract.audit.AuditChainStatus.intact(0, null);
            }

            @Override
            public java.util.List<cn.tolim.spissatus4j.contract.audit.AuditEvent> recent(int limit) {
                return java.util.List.of();
            }

            @Override
            public HealthStatus health() {
                return HealthStatus.UP;
            }

            @Override
            public void close() {
            }
        };
        try (Spissatus facade = SpissatusBuilders.builder()
                .discoverModules(false)
                .algorithmProvider(new TestAlgorithmProvider())
                .keyManager(new TestKeyManager())
                .auditTrail(throwingTrail)
                .auditFailureFailsOperation(true)
                .selfCheckOnStartup(false)
                .build()) {
            assertThrows(AuditException.class,
                    () -> facade.crypto().encrypt(encryptRequest(new byte[]{1}, AAD.empty())));
        }
    }

    @Test
    void startupFailsClosedWhenTheAuditSinkCannotBeWritten() {
        var throwingTrail = new cn.tolim.spissatus4j.contract.audit.AuditTrail() {
            @Override
            public cn.tolim.spissatus4j.contract.audit.AuditEvent append(
                    cn.tolim.spissatus4j.contract.audit.AuditEvent event) {
                throw new AuditException(cn.tolim.spissatus4j.contract.exception.ErrorCode.AUDIT_FAILURE,
                        "down");
            }

            @Override
            public cn.tolim.spissatus4j.contract.audit.AuditChainStatus verify() {
                return cn.tolim.spissatus4j.contract.audit.AuditChainStatus.intact(0, null);
            }

            @Override
            public java.util.List<cn.tolim.spissatus4j.contract.audit.AuditEvent> recent(int limit) {
                return java.util.List.of();
            }

            @Override
            public HealthStatus health() {
                return HealthStatus.DOWN;
            }

            @Override
            public void close() {
            }
        };
        assertThrows(ConfigurationException.class, () -> SpissatusBuilders.builder()
                .discoverModules(false)
                .algorithmProvider(new TestAlgorithmProvider())
                .keyManager(new TestKeyManager())
                .auditTrail(throwingTrail)
                .build());
    }

    @Test
    void closeIsIdempotentAndFailClosed() {
        Spissatus facade = facade();
        facade.close();
        facade.close();
        assertEquals(cn.tolim.spissatus4j.contract.runtime.RuntimeState.CLOSED, facade.state());
        assertThrows(RuntimeSecurityException.class,
                () -> facade.crypto().encrypt(encryptRequest(new byte[]{1}, AAD.empty())));
    }

    @Test
    void envelopeRequiresAnEnvelopeService() {
        try (Spissatus facade = facade()) {
            assertThrows(ConfigurationException.class, facade::envelopeService);
        }
    }
}