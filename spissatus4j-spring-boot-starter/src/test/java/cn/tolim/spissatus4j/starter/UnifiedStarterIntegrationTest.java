package cn.tolim.spissatus4j.starter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.facade.Spissatus;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.exception.EnvelopeException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyGenerationRequest;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.unified.UnifiedDecryptRequest;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptRequest;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptionResult;
import cn.tolim.spissatus4j.starter.autoconfigure.SpissatusAutoConfiguration;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class UnifiedStarterIntegrationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SpissatusAutoConfiguration.class));

    private static CallerContext caller() {
        return CallerContext.of("unified-test", "unified-tenant", Set.of("crypto-user"));
    }

    private static KeyId generate(Spissatus facade, String id, KeyType type,
                                  AlgorithmId algorithm) {
        return facade.keyManager().generate(KeyGenerationRequest.builder(type, algorithm,
                        Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT))
                .keyId(KeyId.of(id)).tenantId(caller().tenantId()).build(), caller()).keyId();
    }

    @Test
    void realModulesRoundTripJsonTlvAndText() {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            KeyId key = generate(facade, "unified-aes", KeyType.AES, AlgorithmId.AES_GCM);
            byte[] plaintext = "real module unified".getBytes(StandardCharsets.UTF_8);
            UnifiedEncryptionResult result = facade.encrypt(UnifiedEncryptRequest.builder(
                            key, plaintext, caller())
                    .attributes(Map.of("trace", "unified"))
                    .build());
            assertThat(result.envelope().version()).isEqualTo(2);
            assertThat(result.envelope().headerHash()).hasSize(32);
            assertThat(result.selection().selectedAlgorithm()).isEqualTo(AlgorithmId.AES_GCM);
            assertThat(facade.decryptEnvelope(facade.envelopeService().encode(
                    result.envelope(), EnvelopeFormat.JSON), caller())).isEqualTo(plaintext);

            for (EnvelopeFormat format : EnvelopeFormat.values()) {
                byte[] encoded = facade.envelopeService().encode(result.envelope(), format);
                assertThat(facade.decrypt(UnifiedDecryptRequest.builder(encoded, caller()).build()))
                        .isEqualTo(plaintext);
                String text = facade.envelopeService().encodeText(result.envelope(), format,
                        BinaryEncoding.BASE64);
                assertThat(facade.decrypt(UnifiedDecryptRequest.builder(text, caller()).build()))
                        .isEqualTo(plaintext);
            }

            var tampered = result.envelope().toBuilder()
                    .headerHash(new byte[32]).build();
            byte[] encoded = facade.envelopeService().encode(tampered, EnvelopeFormat.JSON);
            assertThatThrownBy(() -> facade.decrypt(
                    UnifiedDecryptRequest.builder(encoded, caller()).build()))
                    .isInstanceOfSatisfying(EnvelopeException.class,
                            failure -> assertThat(failure.errorCode())
                                    .isEqualTo(ErrorCode.ENVELOPE_BINDING_MISMATCH));
        });
    }

    @Test
    void autoSelectionWorksForGmCompliance() {
        runner.withPropertyValues("spissatus.keys.provider=memory",
                "spissatus.compliance-mode=GM").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            KeyId key = generate(facade, "unified-sm4", KeyType.SM4, AlgorithmId.SM4_GCM);
            byte[] plaintext = "国密统一入口".getBytes(StandardCharsets.UTF_8);
            UnifiedEncryptionResult result = facade.encrypt(UnifiedEncryptRequest.builder(
                    key, plaintext, caller()).build());
            assertThat(result.selection().selectedAlgorithm()).isEqualTo(AlgorithmId.SM4_GCM);
            byte[] encoded = facade.envelopeService().encode(result.envelope(),
                    EnvelopeFormat.JSON);
            assertThat(facade.decrypt(UnifiedDecryptRequest.builder(encoded, caller()).build()))
                    .isEqualTo(plaintext);
        });
    }

    @Test
    void candidateKeysAndAlgorithmOrderAreDeterministic() {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            KeyId aes = generate(facade, "candidate-aes", KeyType.AES, AlgorithmId.AES_GCM);
            KeyId chacha = generate(facade, "candidate-chacha", KeyType.SYMMETRIC,
                    AlgorithmId.CHACHA20_POLY1305);
            byte[] plaintext = "candidate order".getBytes(StandardCharsets.UTF_8);
            UnifiedEncryptionResult result = facade.encrypt(UnifiedEncryptRequest.builder(
                            java.util.List.of(chacha, aes), plaintext, caller())
                    .candidates(java.util.List.of(AlgorithmId.CHACHA20_POLY1305,
                            AlgorithmId.AES_GCM))
                    .build());
            assertThat(result.selection().selectedAlgorithm())
                    .isEqualTo(AlgorithmId.CHACHA20_POLY1305);
            assertThat(result.selection().selectedKeyId()).isEqualTo(chacha);
            byte[] encoded = facade.envelopeService().encode(result.envelope(),
                    EnvelopeFormat.JSON);
            assertThat(facade.decrypt(UnifiedDecryptRequest.builder(encoded, caller()).build()))
                    .isEqualTo(plaintext);
        });
    }

    @Test
    void familyReuseMustBeExplicit() {
        runner.withPropertyValues("spissatus.keys.provider=memory",
                "spissatus.selection.allow-family-reuse=true").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            KeyId aes = generate(facade, "family-aes", KeyType.AES, AlgorithmId.AES_GCM);
            byte[] plaintext = "family reuse".getBytes(StandardCharsets.UTF_8);
            assertThatThrownBy(() -> facade.encrypt(UnifiedEncryptRequest.builder(
                            aes, plaintext, caller())
                    .algorithm(AlgorithmId.AES_CBC).build()))
                    .isInstanceOfSatisfying(
                            cn.tolim.spissatus4j.contract.exception.KeyException.class,
                            failure -> assertThat(failure.errorCode())
                                    .isEqualTo(ErrorCode.KEY_ALGORITHM_MISMATCH));
            UnifiedEncryptionResult result = facade.encrypt(UnifiedEncryptRequest.builder(
                            aes, plaintext, caller())
                    .algorithm(AlgorithmId.AES_CBC)
                    .allowFamilyReuse(true)
                    .build());
            assertThat(result.selection().selectedAlgorithm()).isEqualTo(AlgorithmId.AES_CBC);
            byte[] encoded = facade.envelopeService().encode(result.envelope(),
                    EnvelopeFormat.TLV);
            assertThat(facade.decrypt(UnifiedDecryptRequest.builder(encoded, caller()).build()))
                    .isEqualTo(plaintext);
        });
    }

    @Test
    void missingCandidateKeyDoesNotAbortAnOrderedList() {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            KeyId valid = generate(facade, "candidate-valid", KeyType.AES, AlgorithmId.AES_GCM);
            byte[] plaintext = "candidate fallback".getBytes(StandardCharsets.UTF_8);
            UnifiedEncryptionResult result = facade.encrypt(UnifiedEncryptRequest.builder(
                            java.util.List.of(KeyId.of("missing-key"), valid), plaintext, caller())
                    .build());
            assertThat(result.selection().selectedKeyId()).isEqualTo(valid);
            byte[] encoded = facade.envelopeService().encode(result.envelope(),
                    EnvelopeFormat.JSON);
            assertThat(facade.decrypt(UnifiedDecryptRequest.builder(encoded, caller()).build()))
                    .isEqualTo(plaintext);
        });
    }

    @Test
    void operatorFamilyReuseSettingIsACeiling() {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            KeyId aes = generate(facade, "ceiling-aes", KeyType.AES, AlgorithmId.AES_GCM);
            assertThatThrownBy(() -> facade.encrypt(UnifiedEncryptRequest.builder(
                            aes, "ceiling".getBytes(StandardCharsets.UTF_8), caller())
                    .algorithm(AlgorithmId.AES_CBC)
                    .allowFamilyReuse(true)
                    .build()))
                    .isInstanceOfSatisfying(
                            cn.tolim.spissatus4j.contract.exception.KeyException.class,
                            failure -> assertThat(failure.errorCode())
                                    .isEqualTo(ErrorCode.KEY_ALGORITHM_MISMATCH));
        });
    }

    @Test
    void crossTenantRoleCanUseTheUnifiedEntry() {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            KeyId key = generate(facade, "cross-tenant-aes", KeyType.AES, AlgorithmId.AES_GCM);
            CallerContext admin = CallerContext.of("admin", "other-tenant",
                    java.util.Set.of("crypto-admin"));
            byte[] plaintext = "cross tenant".getBytes(StandardCharsets.UTF_8);
            UnifiedEncryptionResult result = facade.encrypt(UnifiedEncryptRequest.builder(
                    key, plaintext, admin).build());
            byte[] encoded = facade.envelopeService().encode(result.envelope(),
                    EnvelopeFormat.JSON);
            assertThat(facade.decrypt(UnifiedDecryptRequest.builder(encoded, admin).build()))
                    .isEqualTo(plaintext);
        });
    }

    @Test
    void unifiedEntryRejectsAsymmetricAlgorithms() {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            KeyId rsa = generate(facade, "unified-rsa", KeyType.RSA, AlgorithmId.RSA_OAEP);
            assertThatThrownBy(() -> facade.encrypt(UnifiedEncryptRequest.builder(
                            rsa, "asymmetric".getBytes(StandardCharsets.UTF_8), caller())
                    .algorithm(AlgorithmId.RSA_OAEP).build()))
                    .isInstanceOf(cn.tolim.spissatus4j.contract.exception.CryptoException.class);
        });
    }

    @Test
    void autoSelectionUsesAnExactChaChaKey() {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            KeyId key = generate(facade, "unified-chacha", KeyType.SYMMETRIC,
                    AlgorithmId.CHACHA20_POLY1305);
            byte[] plaintext = "chacha unified".getBytes(StandardCharsets.UTF_8);
            UnifiedEncryptionResult result = facade.encrypt(UnifiedEncryptRequest.builder(
                    key, plaintext, caller()).build());
            assertThat(result.selection().selectedAlgorithm())
                    .isEqualTo(AlgorithmId.CHACHA20_POLY1305);
            byte[] encoded = facade.envelopeService().encode(result.envelope(),
                    EnvelopeFormat.TLV);
            assertThat(facade.decrypt(UnifiedDecryptRequest.builder(encoded, caller()).build()))
                    .isEqualTo(plaintext);
        });
    }

    @Test
    void starterDoesNotCreateAWebServerContext() {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context ->
                assertThat(context.getSourceApplicationContext().getClass().getName())
                        .doesNotContain("WebServerApplicationContext"));
    }
}