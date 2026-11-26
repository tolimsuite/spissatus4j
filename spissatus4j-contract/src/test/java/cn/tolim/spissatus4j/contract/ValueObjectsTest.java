package cn.tolim.spissatus4j.contract;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.DecryptRequest;
import cn.tolim.spissatus4j.contract.crypto.DerivedKey;
import cn.tolim.spissatus4j.contract.crypto.EncryptRequest;
import cn.tolim.spissatus4j.contract.crypto.EncryptedData;
import cn.tolim.spissatus4j.contract.crypto.KdfParameters;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.crypto.StreamHeader;
import cn.tolim.spissatus4j.contract.crypto.VerifyRequest;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ValueObjectsTest {

    private static final CallerContext CALLER =
            CallerContext.of("caller", "tenant", Set.of("role"));

    @Test
    void keyIdentifiersValidateAndNormalize() {
        assertEquals("key-1", KeyId.of("key-1").value());
        assertThrows(IllegalArgumentException.class, () -> KeyId.of(""));
        assertThrows(IllegalArgumentException.class, () -> KeyId.of("bad key"));
        assertThrows(IllegalArgumentException.class, () -> new KeyVersion(0));
        assertEquals(new KeyVersion(2), KeyVersion.first().next());
        assertEquals(1, KeyVersion.of(2).compareTo(KeyVersion.first()));
    }

    @Test
    void copyableValuesAreDefensive() {
        byte[] raw = new byte[]{1, 2, 3};
        Nonce nonce = Nonce.of(raw);
        Salt salt = Salt.of(raw);
        AAD aad = AAD.of(raw);
        raw[0] = 9;
        assertArrayEquals(new byte[]{1, 2, 3}, nonce.asBytes());
        assertArrayEquals(new byte[]{1, 2, 3}, salt.asBytes());
        assertArrayEquals(new byte[]{1, 2, 3}, aad.asBytes());
        assertFalse(nonce.toString().contains("01"));
        assertFalse(salt.toString().contains("01"));
        assertTrue(aad.toString().contains("length=3"));

        byte[] ciphertext = new byte[]{4, 5};
        EncryptedData data = EncryptedData.builder()
                .algorithm(AlgorithmId.AES_GCM)
                .keyId(KeyId.of("key"))
                .keyVersion(KeyVersion.first())
                .nonce(nonce).ciphertext(ciphertext).tag(new byte[]{6}).aad(aad)
                .createdAt(Instant.now()).build();
        ciphertext[0] = 9;
        assertArrayEquals(new byte[]{4, 5}, data.ciphertext());
        byte[] returned = data.tag();
        returned[0] = 9;
        assertArrayEquals(new byte[]{6}, data.tag());
        assertFalse(data.toString().contains("04"));
    }

    @Test
    void callersAreImmutableAndAnonymousIsRecognized() {
        CallerContext caller = new CallerContext("caller", "tenant", Set.of("a"),
                "prod", Map.of("k", "v"));
        assertEquals("caller", caller.callerId());
        assertTrue(caller.hasRole("a"));
        assertFalse(caller.isAnonymous());
        assertTrue(CallerContext.anonymous().isAnonymous());
        assertThrows(IllegalArgumentException.class, () -> new CallerContext(" ", "tenant", Set.of(),
                "prod", Map.of()));
    }

    @Test
    void policyDecisionMergesStrictest() {
        PolicyDecision allow = PolicyDecision.allow("a");
        PolicyDecision warn = PolicyDecision.warn("DEPRECATED", "warning", "b");
        PolicyDecision deny = PolicyDecision.deny("DENIED", "denied", "c");
        assertEquals(allow, PolicyDecision.strictest(allow, allow));
        assertEquals(warn, PolicyDecision.strictest(allow, warn));
        assertEquals(warn, PolicyDecision.strictest(warn, allow));
        assertEquals(deny, PolicyDecision.strictest(warn, deny));
        assertTrue(PolicyDecision.strictest(null, allow).allowed());
        assertTrue(PolicyDecision.strictest(null, null).denied());
    }

    @Test
    void kdfParametersValidateAndHideInfo() {
        KdfParameters.Argon2id argon = KdfParameters.argon2idDefault();
        assertEquals(AlgorithmId.ARGON2ID, argon.algorithm());
        assertEquals("65536", argon.toMap().get("memoryKib"));
        assertThrows(IllegalArgumentException.class,
                () -> new KdfParameters.Argon2id(1, 1, 1, 32, 19));
        assertThrows(IllegalArgumentException.class,
                () -> new KdfParameters.Scrypt(1000, 8, 1, 32));
        assertThrows(IllegalArgumentException.class,
                () -> new KdfParameters.Pbkdf2(0, 32, "HmacSHA256"));
        KdfParameters.Hkdf hkdf = new KdfParameters.Hkdf(32, new byte[]{1, 2, 3}, "HmacSHA256");
        assertEquals(3, hkdf.info().length);
        assertFalse(hkdf.toString().contains("AQID"));
        byte[] info = hkdf.info();
        info[0] = 9;
        assertArrayEquals(new byte[]{1, 2, 3}, hkdf.info());
    }

    @Test
    void derivedKeyNeverPrintsBytes() {
        DerivedKey key = new DerivedKey(AlgorithmId.HKDF, new byte[]{1, 2, 3}, Salt.empty(),
                KdfParameters.hkdfDefault(new byte[0]), false);
        assertFalse(key.toString().contains("01"));
        assertEquals(3, key.length());
        byte[] copy = key.key();
        copy[0] = 9;
        assertArrayEquals(new byte[]{1, 2, 3}, key.key());
    }

    @Test
    void requestsAndDescriptorsCopyArrays() {
        byte[] plaintext = new byte[]{1};
        EncryptRequest request = EncryptRequest.builder(AlgorithmId.AES_GCM, KeyId.of("key"),
                plaintext, CALLER).build();
        plaintext[0] = 9;
        assertArrayEquals(new byte[]{1}, request.plaintext());

        KeyDescriptor descriptor = KeyDescriptor.builder()
                .keyId(KeyId.of("key")).version(KeyVersion.first()).type(KeyType.AES)
                .algorithm(AlgorithmId.AES_GCM).keyBits(256).state(KeyState.ACTIVE)
                .usages(Set.of(KeyUsage.ENCRYPT)).tenantId("tenant").createdAt(Instant.now())
                .build();
        assertTrue(descriptor.isActive());
        assertTrue(descriptor.supportsUsage(KeyUsage.ENCRYPT));
        assertFalse(descriptor.toString().contains("attributes"));
        var updated = descriptor.withUsageCount(5);
        assertEquals(5, updated.usageCount());
        assertEquals(KeyState.ACTIVE, updated.state());

        DecryptRequest decrypt = DecryptRequest.from(EncryptedData.builder()
                .algorithm(AlgorithmId.AES_GCM).keyId(KeyId.of("key"))
                .keyVersion(KeyVersion.first()).nonce(Nonce.empty())
                .ciphertext(new byte[]{1}).tag(new byte[]{2}).createdAt(Instant.now()).build(), CALLER);
        assertNotEquals(null, decrypt.toBuilder().build());
    }

    @Test
    void verifyRequestRequiresAKeySource() {
        assertThrows(IllegalArgumentException.class,
                () -> VerifyRequest.builder(AlgorithmId.ED25519, new byte[]{1}, new byte[]{2}, CALLER)
                        .build());
        VerifyRequest request = VerifyRequest.builder(AlgorithmId.ED25519, new byte[]{1},
                        new byte[]{2}, CALLER)
                .keyId(KeyId.of("key")).build();
        assertEquals(KeyId.of("key"), request.keyId());
        assertEquals(Operation.VERIFY, Operation.VERIFY);
    }

    @Test
    void keyManagerDependenciesDoNotPrintSecrets() {
        var policy = new cn.tolim.spissatus4j.contract.policy.PolicyEngine() {
            @Override
            public String engineId() {
                return "test";
            }

            @Override
            public cn.tolim.spissatus4j.contract.policy.PolicyDecision evaluate(
                    cn.tolim.spissatus4j.contract.policy.PolicyRequest request) {
                return cn.tolim.spissatus4j.contract.policy.PolicyDecision.allow("test");
            }

            @Override
            public cn.tolim.spissatus4j.contract.runtime.HealthStatus health() {
                return cn.tolim.spissatus4j.contract.runtime.HealthStatus.UP;
            }
        };
        var audit = new cn.tolim.spissatus4j.contract.audit.AuditTrail() {
            @Override
            public cn.tolim.spissatus4j.contract.audit.AuditEvent append(
                    cn.tolim.spissatus4j.contract.audit.AuditEvent event) {
                return event;
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
            public cn.tolim.spissatus4j.contract.runtime.HealthStatus health() {
                return cn.tolim.spissatus4j.contract.runtime.HealthStatus.UP;
            }

            @Override
            public void close() {
            }
        };
        var dependencies = new cn.tolim.spissatus4j.contract.key.KeyManagerDependencies(
                policy, audit, java.time.Clock.systemUTC(), java.util.List.of(), java.util.List.of(),
                Map.of("spissatus.key.master.password", "hunter2",
                        "spissatus.audit.hmac-key", "secret"));
        assertFalse(dependencies.toString().contains("hunter2"));
        assertFalse(dependencies.toString().contains("secret"));
        assertTrue(dependencies.toString().contains("redacted"));
    }

    @Test
    void streamHeaderBoundsChunkSize() {
        assertThrows(IllegalArgumentException.class, () -> new StreamHeader(1,
                AlgorithmId.AES_GCM, KeyId.of("key"), KeyVersion.first(),
                Nonce.of(new byte[12]), 128, AAD.empty(), Instant.now(), Map.of()));
        StreamHeader header = new StreamHeader(1, AlgorithmId.AES_GCM, KeyId.of("key"),
                KeyVersion.first(), Nonce.of(new byte[12]), 4096, AAD.empty(),
                Instant.now(), Map.of("k", "v"));
        assertEquals(4096, header.chunkSize());
        assertFalse(header.toString().contains("nonce"));
    }
}