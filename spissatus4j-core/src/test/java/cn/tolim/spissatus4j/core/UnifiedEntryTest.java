package cn.tolim.spissatus4j.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.facade.Spissatus;
import cn.tolim.spissatus4j.contract.audit.AuditEventType;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.EncryptRequest;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.PolicyException;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.unified.SelectionReport;
import cn.tolim.spissatus4j.contract.unified.UnifiedDecryptRequest;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptRequest;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptionResult;
import cn.tolim.spissatus4j.core.builder.SpissatusBuilders;
import cn.tolim.spissatus4j.core.testkit.TestAlgorithmProvider;
import cn.tolim.spissatus4j.core.testkit.TestEnvelopeService;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class UnifiedEntryTest {

    private static final CallerContext CALLER =
            CallerContext.of("tester", TestKeyManager.TENANT, Set.of("crypto-user"));

    private Spissatus facade() {
        return facade(new TestEnvelopeService());
    }

    private Spissatus facade(TestEnvelopeService envelopeService) {
        return SpissatusBuilders.builder()
                .discoverModules(false)
                .algorithmProvider(new TestAlgorithmProvider())
                .keyManager(new TestKeyManager())
                .envelopeService(envelopeService)
                .setting("spissatus.selection.allow-legacy-v1", "true")
                .build();
    }

    private UnifiedEncryptRequest request(byte[] plaintext) {
        return UnifiedEncryptRequest.builder(TestKeyManager.KEY_ID, plaintext, CALLER).build();
    }

    @Test
    void encryptsAndDecryptsThroughUnifiedEntry() {
        try (Spissatus facade = facade()) {
            byte[] plaintext = "unified hello".getBytes(StandardCharsets.UTF_8);
            UnifiedEncryptionResult result = facade.encrypt(request(plaintext));

            assertEquals(2, result.envelope().version());
            assertEquals(32, result.envelope().headerHash().length);
            assertEquals(AlgorithmId.AES_GCM, result.selection().selectedAlgorithm());
            assertTrue(result.selection().selected());
            Envelope decoded = facade.envelopeService().decode(
                    facade.envelopeService().encode(result.envelope(), EnvelopeFormat.JSON));
            assertEquals(2, decoded.version());
            assertArrayEquals(result.envelope().headerHash(), decoded.headerHash());
            assertArrayEquals(result.envelope().ciphertext(), decoded.ciphertext());

            byte[] encoded = facade.envelopeService().encode(result.envelope(), EnvelopeFormat.JSON);
            byte[] decrypted = facade.decrypt(UnifiedDecryptRequest.builder(encoded, CALLER).build());
            assertArrayEquals(plaintext, decrypted);

            String text = facade.envelopeService().encodeText(result.envelope(),
                    EnvelopeFormat.JSON, BinaryEncoding.BASE64);
            byte[] fromText = facade.decrypt(UnifiedDecryptRequest.builder(text, CALLER).build());
            assertArrayEquals(plaintext, fromText);
        }
    }

    @Test
    void defaultDecryptEnvelopeAlsoVerifiesV2Binding() {
        try (Spissatus facade = facade()) {
            byte[] plaintext = "facade envelope".getBytes(StandardCharsets.UTF_8);
            UnifiedEncryptionResult result = facade.encrypt(request(plaintext));
            byte[] encoded = facade.envelopeService().encode(result.envelope(), EnvelopeFormat.JSON);
            assertArrayEquals(plaintext, facade.decryptEnvelope(encoded, CALLER));
        }
    }

    @Test
    void onePolicyDecisionPerUnifiedOperation() {
        AtomicInteger evaluations = new AtomicInteger();
        PolicyEngine counting = new PolicyEngine() {
            @Override
            public String engineId() {
                return "counting";
            }

            @Override
            public PolicyDecision evaluate(PolicyRequest request) {
                evaluations.incrementAndGet();
                return PolicyDecision.allow("counting");
            }

            @Override
            public HealthStatus health() {
                return HealthStatus.UP;
            }
        };
        try (Spissatus facade = SpissatusBuilders.builder()
                .discoverModules(false)
                .algorithmProvider(new TestAlgorithmProvider())
                .keyManager(new TestKeyManager())
                .envelopeService(new TestEnvelopeService())
                .policyEngine(counting)
                .build()) {
            facade.encrypt(request(new byte[]{1, 2, 3}));
            assertEquals(1, evaluations.get());
        }
    }

    @Test
    void automaticKeySelectionMakesOnePolicyDecision() {
        AtomicInteger evaluations = new AtomicInteger();
        PolicyEngine counting = new PolicyEngine() {
            @Override
            public String engineId() {
                return "counting-auto";
            }

            @Override
            public PolicyDecision evaluate(PolicyRequest request) {
                evaluations.incrementAndGet();
                return PolicyDecision.allow("counting-auto");
            }

            @Override
            public HealthStatus health() {
                return HealthStatus.UP;
            }
        };
        try (Spissatus facade = SpissatusBuilders.builder()
                .discoverModules(false)
                .algorithmProvider(new TestAlgorithmProvider())
                .keyManager(new TestKeyManager())
                .envelopeService(new TestEnvelopeService())
                .policyEngine(counting)
                .setting("spissatus.selection.allow-auto-key-selection", "true")
                .build()) {
            UnifiedEncryptionResult result = facade.encrypt(
                    UnifiedEncryptRequest.builderAutoKey(new byte[]{1, 2, 3}, CALLER).build());
            assertEquals(TestKeyManager.KEY_ID, result.selection().selectedKeyId());
            assertEquals(1, evaluations.get());
        }
    }

    @Test
    void automaticKeySelectionRequiresTheOperatorSetting() {
        try (Spissatus facade = facade()) {
            PolicyException failure = assertThrows(PolicyException.class,
                    () -> facade.encrypt(UnifiedEncryptRequest.builderAutoKey(
                            new byte[]{1}, CALLER).build()));
            assertEquals(ErrorCode.POLICY_DENIED, failure.errorCode());
        }
    }

    @Test
    void rejectsUnknownAndProhibitedExplicitAlgorithms() {
        try (Spissatus facade = facade()) {
            PolicyException prohibited = assertThrows(PolicyException.class,
                    () -> facade.encrypt(UnifiedEncryptRequest.builder(TestKeyManager.KEY_ID,
                                    new byte[]{1}, CALLER)
                            .algorithm(AlgorithmId.AES_ECB).build()));
            assertEquals(ErrorCode.ALGORITHM_PROHIBITED, prohibited.errorCode());

            PolicyException md5 = assertThrows(PolicyException.class,
                    () -> facade.encrypt(UnifiedEncryptRequest.builder(TestKeyManager.KEY_ID,
                                    new byte[]{1}, CALLER)
                            .algorithm(AlgorithmId.MD5).build()));
            assertEquals(ErrorCode.ALGORITHM_PROHIBITED, md5.errorCode());
        }
    }

    @Test
    void rejectsTamperedMetadataBeforeDecryption() {
        try (Spissatus facade = facade()) {
            UnifiedEncryptionResult result = facade.encrypt(request("bound".getBytes(
                    StandardCharsets.UTF_8)));
            Envelope tampered = result.envelope().toBuilder()
                    .headerHash(new byte[32])
                    .build();
            byte[] encoded = facade.envelopeService().encode(tampered, EnvelopeFormat.JSON);
            EnvelopeException failure = assertThrows(EnvelopeException.class,
                    () -> facade.decrypt(UnifiedDecryptRequest.builder(encoded, CALLER).build()));
            assertEquals(ErrorCode.ENVELOPE_BINDING_MISMATCH, failure.errorCode());

            Envelope changedAttributes = result.envelope().toBuilder()
                    .attributes(Map.of("tampered", "value"))
                    .build();
            byte[] changed = facade.envelopeService().encode(changedAttributes,
                    EnvelopeFormat.JSON);
            EnvelopeException attributeFailure = assertThrows(EnvelopeException.class,
                    () -> facade.decrypt(UnifiedDecryptRequest.builder(changed, CALLER).build()));
            assertEquals(ErrorCode.ENVELOPE_BINDING_MISMATCH, attributeFailure.errorCode());
        }
    }

    @Test
    void rejectsLegacyV1UnlessExplicitlyAllowed() {
        try (Spissatus facade = facade()) {
            byte[] plaintext = "legacy".getBytes(StandardCharsets.UTF_8);
            Envelope v1 = facade.encryptToEnvelope(EncryptRequest.builder(AlgorithmId.AES_GCM,
                            TestKeyManager.KEY_ID, plaintext, CALLER).build(),
                    EnvelopeFormat.JSON, BinaryEncoding.BASE64);
            byte[] encoded = facade.envelopeService().encode(v1, EnvelopeFormat.JSON);

            EnvelopeException denied = assertThrows(EnvelopeException.class,
                    () -> facade.decrypt(UnifiedDecryptRequest.builder(encoded, CALLER).build()));
            assertEquals(ErrorCode.LEGACY_ENVELOPE_DENIED, denied.errorCode());

            byte[] decrypted = facade.decrypt(UnifiedDecryptRequest.builder(encoded, CALLER)
                    .allowLegacyV1(true).build());
            assertArrayEquals(plaintext, decrypted);

            EnvelopeException freshness = assertThrows(EnvelopeException.class,
                    () -> facade.decrypt(UnifiedDecryptRequest.builder(encoded, CALLER)
                            .allowLegacyV1(true).maxAge(Duration.ofMinutes(1)).build()));
            assertEquals(ErrorCode.LEGACY_ENVELOPE_DENIED, freshness.errorCode());
        }
    }

    @Test
    void legacyV1RequiresTheOperatorSettingAsACeiling() {
        try (Spissatus strict = SpissatusBuilders.builder()
                .discoverModules(false)
                .algorithmProvider(new TestAlgorithmProvider())
                .keyManager(new TestKeyManager())
                .envelopeService(new TestEnvelopeService())
                .build()) {
            byte[] plaintext = "legacy-ceiling".getBytes(StandardCharsets.UTF_8);
            Envelope v1 = strict.encryptToEnvelope(EncryptRequest.builder(AlgorithmId.AES_GCM,
                            TestKeyManager.KEY_ID, plaintext, CALLER).build(),
                    EnvelopeFormat.JSON, BinaryEncoding.BASE64);
            byte[] encoded = strict.envelopeService().encode(v1, EnvelopeFormat.JSON);
            EnvelopeException denied = assertThrows(EnvelopeException.class,
                    () -> strict.decrypt(UnifiedDecryptRequest.builder(encoded, CALLER)
                            .allowLegacyV1(true).build()));
            assertEquals(ErrorCode.LEGACY_ENVELOPE_DENIED, denied.errorCode());
        }
    }

    @Test
    void oversizedMaxAgeFailsClosedAsAnEnvelopeError() {
        try (Spissatus facade = facade()) {
            UnifiedEncryptionResult result = facade.encrypt(request(new byte[]{1}));
            byte[] encoded = facade.envelopeService().encode(result.envelope(), EnvelopeFormat.JSON);
            EnvelopeException failure = assertThrows(EnvelopeException.class,
                    () -> facade.decrypt(UnifiedDecryptRequest.builder(encoded, CALLER)
                            .maxAge(Duration.ofSeconds(Long.MAX_VALUE)).build()));
            assertEquals(ErrorCode.ENVELOPE_VALIDATION_FAILED, failure.errorCode());
        }
    }

    @Test
    void expectedContextMustMatch() {
        try (Spissatus facade = facade()) {
            UnifiedEncryptionResult result = facade.encrypt(UnifiedEncryptRequest.builder(
                            TestKeyManager.KEY_ID, "context".getBytes(StandardCharsets.UTF_8), CALLER)
                    .aad(AAD.ofUtf8("tenant-context"))
                    .attributes(Map.of("trace", "abc"))
                    .build());
            byte[] encoded = facade.envelopeService().encode(result.envelope(), EnvelopeFormat.JSON);

            assertThrows(EnvelopeException.class, () -> facade.decrypt(
                    UnifiedDecryptRequest.builder(encoded, CALLER)
                            .expectedAad(AAD.ofUtf8("other")).build()));
            assertThrows(EnvelopeException.class, () -> facade.decrypt(
                    UnifiedDecryptRequest.builder(encoded, CALLER)
                            .expectedAlgorithm(AlgorithmId.CHACHA20_POLY1305).build()));
            assertThrows(EnvelopeException.class, () -> facade.decrypt(
                    UnifiedDecryptRequest.builder(encoded, CALLER)
                            .expectedAttributes(Map.of("trace", "different")).build()));

            byte[] plaintext = facade.decrypt(UnifiedDecryptRequest.builder(encoded, CALLER)
                    .expectedAad(AAD.ofUtf8("tenant-context"))
                    .expectedAlgorithm(AlgorithmId.AES_GCM)
                    .expectedKeyId(TestKeyManager.KEY_ID)
                    .expectedAttributes(Map.of("trace", "abc"))
                    .build());
            assertArrayEquals("context".getBytes(StandardCharsets.UTF_8), plaintext);
        }
    }

    @Test
    void selectionAuditDoesNotContainAttributeValues() {
        try (Spissatus facade = facade()) {
            facade.encrypt(UnifiedEncryptRequest.builder(TestKeyManager.KEY_ID,
                            new byte[]{1}, CALLER)
                    .attributes(Map.of("secret-label", "secret-value"))
                    .build());
            assertTrue(facade.auditTrail().recent(50).stream()
                    .anyMatch(event -> event.type() == AuditEventType.ALGORITHM_SELECTED));
            assertFalse(facade.auditTrail().recent(50).stream()
                    .anyMatch(event -> event.details().containsValue("secret-value")
                            || event.message().contains("secret-value")));
        }
    }

    @Test
    void unifiedEncryptionRequiresEnvelopeService() {
        try (Spissatus facade = SpissatusBuilders.builder()
                .discoverModules(false)
                .algorithmProvider(new TestAlgorithmProvider())
                .keyManager(new TestKeyManager())
                .build()) {
            ConfigurationException failure = assertThrows(ConfigurationException.class,
                    () -> facade.encrypt(request(new byte[]{1})));
            assertEquals(ErrorCode.MISSING_DEPENDENCY, failure.errorCode());
        }
    }

    @Test
    void selectionReportIsConsistent() {
        try (Spissatus facade = facade()) {
            UnifiedEncryptionResult result = facade.encrypt(request(new byte[]{1}));
            SelectionReport report = result.selection();
            assertEquals("AUTO_AEAD", report.profileId());
            assertFalse(report.explicit());
            assertTrue(report.candidates().size() >= 1);
            assertNotNull(report.selectedKeyId());
        }
    }
}