package cn.tolim.spissatus4j.starter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.crypto.MacRequest;
import cn.tolim.spissatus4j.contract.crypto.MacVerifyRequest;
import cn.tolim.spissatus4j.contract.crypto.SignRequest;
import cn.tolim.spissatus4j.contract.crypto.VerifyRequest;
import cn.tolim.spissatus4j.contract.facade.Spissatus;
import cn.tolim.spissatus4j.contract.audit.AuditEventType;
import cn.tolim.spissatus4j.contract.crypto.DecryptRequest;
import cn.tolim.spissatus4j.contract.crypto.EncryptRequest;
import cn.tolim.spissatus4j.contract.crypto.EncryptedData;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.key.KeyGenerationRequest;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.runtime.RuntimeState;
import cn.tolim.spissatus4j.core.builder.SpissatusBuilders;
import cn.tolim.spissatus4j.starter.autoconfigure.SpissatusAutoConfiguration;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class SpissatusAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SpissatusAutoConfiguration.class));

    private static CallerContext caller() {
        return CallerContext.of("test", "test-tenant", Set.of("crypto-user"));
    }

    @Test
    void startsAndPerformsAnEndToEndRoundTrip() {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context -> {
            assertThat(context).hasSingleBean(Spissatus.class);
            Spissatus facade = context.getBean(Spissatus.class);
            assertThat(facade.state()).isEqualTo(RuntimeState.READY);
            assertThat(facade.health().name()).isEqualTo("UP");
            assertThat(facade.capabilities().supports(AlgorithmId.AES_GCM)).isTrue();
            assertThat(facade.capabilities().providers()).isNotEmpty();
            assertThat(facade.capabilities().gmAvailable()).isTrue();

            var key = facade.keyManager().generate(KeyGenerationRequest.builder(
                            KeyType.AES, AlgorithmId.AES_GCM,
                            Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT))
                    .keyId(KeyId.of("autoconfig-aes")).tenantId(caller().tenantId()).build(),
                    caller());
            byte[] plaintext = "spring roundtrip".getBytes(StandardCharsets.UTF_8);
            Envelope envelope = facade.encryptToEnvelope(EncryptRequest.builder(
                            AlgorithmId.AES_GCM, key.keyId(), plaintext, caller())
                    .aad(cn.tolim.spissatus4j.contract.crypto.AAD.ofUtf8("ctx")).build(),
                    EnvelopeFormat.TLV, BinaryEncoding.BASE64);
            byte[] encoded = facade.envelopeService().encode(envelope, EnvelopeFormat.TLV);
            byte[] decrypted = facade.decryptEnvelope(encoded, caller());
            assertThat(decrypted).isEqualTo(plaintext);
            assertThat(facade.auditTrail().verify().intact()).isTrue();
            assertThat(facade.auditTrail().recent(100)).extracting(e -> e.type())
                    .contains(AuditEventType.ENCRYPT, AuditEventType.DECRYPT);
        });
    }

    @Test
    void gmProviderRoundTripThroughTheFacade() {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            var key = facade.keyManager().generate(KeyGenerationRequest.builder(
                            KeyType.SM4, AlgorithmId.SM4_GCM,
                            Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT))
                    .keyId(KeyId.of("gm-sm4")).tenantId(caller().tenantId()).build(), caller());
            byte[] plaintext = "国密 SM4".getBytes(StandardCharsets.UTF_8);
            EncryptedData data = facade.crypto().encrypt(EncryptRequest.builder(
                    AlgorithmId.SM4_GCM, key.keyId(), plaintext, caller()).build());
            byte[] decrypted = facade.crypto().decrypt(DecryptRequest.from(data, caller()));
            assertThat(decrypted).isEqualTo(plaintext);
            assertThat(data.tag().length).isEqualTo(16);
        });
    }

    @Test
    void streamRoundTripThroughTheFacade() throws Exception {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            var key = facade.keyManager().generate(KeyGenerationRequest.builder(
                            KeyType.AES, AlgorithmId.AES_GCM,
                            Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT))
                    .keyId(KeyId.of("stream-aes")).tenantId(caller().tenantId()).build(), caller());
            byte[] plaintext = new byte[10_000];
            new java.util.SplittableRandom(42).nextBytes(plaintext);
            ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
            var request = new cn.tolim.spissatus4j.contract.crypto.StreamEncryptRequest(
                    AlgorithmId.AES_GCM, key.keyId(), null, 1024,
                    cn.tolim.spissatus4j.contract.crypto.AAD.ofUtf8("stream"),
                    caller(), java.util.Map.of());
            try (var output = facade.crypto().openEncryptingStream(encrypted, request)) {
                output.write(plaintext);
            }
            try (var input = facade.crypto().openDecryptingStream(
                    new ByteArrayInputStream(encrypted.toByteArray()), caller())) {
                assertThat(input.readAllBytes()).isEqualTo(plaintext);
            }
            try (var input = facade.crypto().openDecryptingStream(
                    new ByteArrayInputStream(encrypted.toByteArray()), caller(), 1)) {
                assertThat(input.readAllBytes())
                        .isEqualTo(java.util.Arrays.copyOfRange(plaintext, 1024, plaintext.length));
            }
        });
    }

    @Test
    void sm2KeyWrappingIsWiredThroughTheKeyManager() {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            var kek = facade.keyManager().generate(KeyGenerationRequest.builder(
                            KeyType.SM2, AlgorithmId.SM2,
                            Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT,
                                    KeyUsage.WRAP, KeyUsage.UNWRAP))
                    .keyId(KeyId.of("gm-kek")).tenantId(caller().tenantId()).build(), caller());
            byte[] dek = new byte[32];
            new java.util.SplittableRandom(7).nextBytes(dek);
            byte[] wrapped = facade.keyManager().wrapKey(kek.keyId(), kek.version(),
                    AlgorithmId.SM2, dek, caller());
            assertThat(wrapped).isNotEmpty();
            assertThat(facade.keyManager().unwrapKey(kek.keyId(), kek.version(),
                    AlgorithmId.SM2, wrapped, caller())).isEqualTo(dek);
        });
    }

    @Test
    void gmComplianceModeRejectsNonGmAlgorithms() {
        runner.withPropertyValues("spissatus.keys.provider=memory",
                "spissatus.compliance-mode=GM").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            assertThat(facade.capabilities().complianceMode().name()).isEqualTo("GM");
            assertThatThrownBy(() -> facade.keyManager().generate(
                            KeyGenerationRequest.builder(KeyType.AES, AlgorithmId.AES_GCM,
                                    Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT))
                                    .keyId(KeyId.of("gm-denied-aes")).tenantId(caller().tenantId())
                                    .build(), caller()))
                    .isInstanceOf(cn.tolim.spissatus4j.contract.exception.PolicyException.class);
            var key = facade.keyManager().generate(KeyGenerationRequest.builder(
                            KeyType.SM4, AlgorithmId.SM4_GCM,
                            Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT))
                    .keyId(KeyId.of("gm-allowed-sm4")).tenantId(caller().tenantId()).build(),
                    caller());
            byte[] plaintext = "gm compliant".getBytes(StandardCharsets.UTF_8);
            var data = facade.crypto().encrypt(EncryptRequest.builder(AlgorithmId.SM4_GCM,
                    key.keyId(), plaintext, caller()).build());
            assertThat(facade.crypto().decrypt(DecryptRequest.from(data, caller())))
                    .isEqualTo(plaintext);
        });
    }

    @Test
    void rateLimitIsConsumedOncePerOperation() {
        runner.withPropertyValues("spissatus.keys.provider=memory",
                "spissatus.policy.rate-limit-per-minute=3").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            var key = facade.keyManager().generate(KeyGenerationRequest.builder(
                            KeyType.AES, AlgorithmId.AES_GCM,
                            Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT))
                    .keyId(KeyId.of("rate-limited-aes")).tenantId(caller().tenantId()).build(),
                    caller());
            EncryptedData data = facade.crypto().encrypt(EncryptRequest.builder(AlgorithmId.AES_GCM,
                    key.keyId(), "one token".getBytes(StandardCharsets.UTF_8), caller()).build());
            assertThat(facade.crypto().decrypt(DecryptRequest.from(data, caller())))
                    .isEqualTo("one token".getBytes(StandardCharsets.UTF_8));
        });
    }

    @Test
    void incompleteDecryptingStreamIsRecordedAsFailure() {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            var key = facade.keyManager().generate(KeyGenerationRequest.builder(
                            KeyType.AES, AlgorithmId.AES_GCM,
                            Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT))
                    .keyId(KeyId.of("stream-check")).tenantId(caller().tenantId()).build(), caller());
            byte[] plaintext = new byte[5_000];
            ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
            var request = new cn.tolim.spissatus4j.contract.crypto.StreamEncryptRequest(
                    AlgorithmId.AES_GCM, key.keyId(), null, 1024,
                    cn.tolim.spissatus4j.contract.crypto.AAD.empty(), caller(), java.util.Map.of());
            try (var output = facade.crypto().openEncryptingStream(encrypted, request)) {
                output.write(plaintext);
            }
            try (var input = facade.crypto().openDecryptingStream(
                    new ByteArrayInputStream(encrypted.toByteArray()), caller())) {
                input.readNBytes(100);
            } catch (java.io.IOException ignored) {
                // The completion assertion below is what matters.
            }
            assertThat(facade.auditTrail().recent(100)).extracting(e -> e.type())
                    .contains(AuditEventType.STREAM_FAILED);
        });
    }

    @Test
    void eciesRoundTripUsesTheConfiguredProvider() {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            var key = facade.keyManager().generate(KeyGenerationRequest.builder(
                            KeyType.EC, AlgorithmId.ECIES,
                            Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT))
                    .keyId(KeyId.of("ecies-key")).tenantId(caller().tenantId()).build(), caller());
            byte[] plaintext = "ecies payload".getBytes(StandardCharsets.UTF_8);
            var data = facade.crypto().encrypt(EncryptRequest.builder(AlgorithmId.ECIES,
                    key.keyId(), plaintext, caller()).build());
            assertThat(facade.crypto().decrypt(DecryptRequest.from(data, caller())))
                    .isEqualTo(plaintext);
            byte[] tampered = data.ciphertext();
            tampered[tampered.length - 1] ^= 1;
            var bad = DecryptRequest.builder(data.algorithm(), data.keyId(), tampered, caller())
                    .keyVersion(data.keyVersion()).build();
            assertThatThrownBy(() -> facade.crypto().decrypt(bad))
                    .isInstanceOf(cn.tolim.spissatus4j.contract.exception.CryptoException.class);

            Envelope envelope = facade.encryptToEnvelope(EncryptRequest.builder(
                            AlgorithmId.ECIES, key.keyId(), plaintext, caller()).build(),
                    EnvelopeFormat.JSON, BinaryEncoding.BASE64);
            byte[] encoded = facade.envelopeService().encode(envelope, envelope.format());
            assertThat(facade.decryptEnvelope(encoded, caller())).isEqualTo(plaintext);
        });
    }

    @Test
    void cmacAndLegacyRsaSignatureAreAvailableThroughTheFacade() {
        runner.withPropertyValues("spissatus.keys.provider=memory").run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            var macKey = facade.keyManager().generate(KeyGenerationRequest.builder(
                            KeyType.AES, AlgorithmId.AES_GCM,
                            Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.MAC))
                    .keyId(KeyId.of("cmac-aes")).tenantId(caller().tenantId()).build(), caller());
            byte[] data = "cmac data".getBytes(StandardCharsets.UTF_8);
            byte[] tag = facade.crypto().mac(new MacRequest(AlgorithmId.CMAC_AES,
                    macKey.keyId(), null, data, caller()));
            assertThat(tag.length).isEqualTo(16);
            assertThat(facade.crypto().verifyMac(new MacVerifyRequest(AlgorithmId.CMAC_AES,
                    macKey.keyId(), null, data, tag, caller()))).isTrue();

            var rsaKey = facade.keyManager().generate(KeyGenerationRequest.builder(
                            KeyType.RSA, AlgorithmId.RSA_PKCS1_SIGNATURE,
                            Set.of(KeyUsage.SIGN, KeyUsage.VERIFY))
                    .keyId(KeyId.of("legacy-rsa")).tenantId(caller().tenantId()).build(),
                    caller());
            byte[] message = "legacy signature".getBytes(StandardCharsets.UTF_8);
            byte[] signature = facade.crypto().sign(SignRequest.builder(
                    AlgorithmId.RSA_PKCS1_SIGNATURE, rsaKey.keyId(), message, caller()).build());
            assertThat(facade.crypto().verify(VerifyRequest.builder(
                    AlgorithmId.RSA_PKCS1_SIGNATURE, message, signature, caller())
                    .keyId(rsaKey.keyId()).build())).isTrue();
        });
    }




    @Test
    void fipsModeFailsClosedWithoutAFipsProvider() {
        runner.withPropertyValues("spissatus.keys.provider=memory",
                "spissatus.provider.fips=true").run(context ->
                assertThat(context).hasFailed());
        runner.withPropertyValues("spissatus.keys.provider=memory",
                "spissatus.provider.fips=true",
                "spissatus.provider.bouncycastle=false").run(context ->
                assertThat(context).hasFailed());
        runner.withPropertyValues("spissatus.keys.provider=memory",
                "spissatus.compliance-mode=FIPS").run(context ->
                assertThat(context).hasFailed());
        runner.withPropertyValues("spissatus.keys.provider=memory",
                "spissatus.provider.fips=true",
                "spissatus.provider.bouncycastle=false",
                "spissatus.self-check.on-startup=false").run(context ->
                assertThat(context).hasFailed());
    }

    @Test
    void disabledPropertyPreventsTheFacadeBean() {
        runner.withPropertyValues("spissatus.enabled=false").run(context ->
                assertThat(context).doesNotHaveBean(Spissatus.class));
    }

    @Test
    void fileProviderPersistsKeysAcrossContexts(@TempDir Path directory) {
        String master = "correct horse battery staple";
        runner.withPropertyValues(
                "spissatus.keys.provider=file",
                "spissatus.keys.file-directory=" + directory,
                "spissatus.keys.master-password=" + master).run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            facade.keyManager().generate(KeyGenerationRequest.builder(
                            KeyType.AES, AlgorithmId.AES_GCM,
                            Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT))
                    .keyId(KeyId.of("persisted-aes")).tenantId(caller().tenantId()).build(),
                    caller());
        });
        runner.withPropertyValues(
                "spissatus.keys.provider=file",
                "spissatus.keys.file-directory=" + directory,
                "spissatus.keys.master-password=" + master).run(context -> {
            Spissatus facade = context.getBean(Spissatus.class);
            byte[] plaintext = "persisted".getBytes(StandardCharsets.UTF_8);
            EncryptedData data = facade.crypto().encrypt(EncryptRequest.builder(
                    AlgorithmId.AES_GCM, KeyId.of("persisted-aes"), plaintext, caller()).build());
            assertThat(facade.crypto().decrypt(DecryptRequest.from(data, caller())))
                    .isEqualTo(plaintext);
        });
    }
}