package cn.tolim.spissatus4j.key.provider;

import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.DECRYPT;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.ENCRYPT;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.MAC;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.key.KeyGenerationRequest;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.spi.StoredKey;
import cn.tolim.spissatus4j.key.internal.KeyMaterialCodec;
import cn.tolim.spissatus4j.key.manager.DefaultKeyManager;
import cn.tolim.spissatus4j.key.support.TestSupport;
import cn.tolim.spissatus4j.key.support.TestSupport.MutableClock;
import cn.tolim.spissatus4j.key.support.TestSupport.RecordingAuditTrail;
import cn.tolim.spissatus4j.key.support.TestSupport.StubPolicyEngine;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class EnvironmentKeyProviderTest {

    private static final byte[] AES_MATERIAL = material(32, 0x51);
    private static final byte[] HMAC_MATERIAL = material(20, 0x61);
    private static final CallerContext CALLER = TestSupport.caller();

    private final EnvironmentKeyProvider provider = new EnvironmentKeyProvider("TEST_", Map.of(
            "TEST_DEMO_AES", Base64.getEncoder().encodeToString(AES_MATERIAL),
            "TEST_DEMO_HMAC_V2", Base64.getEncoder().encodeToString(HMAC_MATERIAL),
            "TEST_CORRUPT", "%%%not-base64%%%",
            "OTHER_IGNORED", Base64.getEncoder().encodeToString(AES_MATERIAL)));

    @Test
    void readsSymmetricKeysAndDerivesDescriptors() {
        Optional<StoredKey> loaded = provider.load(KeyId.of("DEMO_AES"), KeyVersion.first());
        assertTrue(loaded.isPresent());
        StoredKey storedKey = loaded.orElseThrow();
        assertArrayEquals(AES_MATERIAL, storedKey.material());
        assertFalse(storedKey.encrypted());
        assertEquals(KeyMaterialCodec.RAW, storedKey.materialFormat());
        assertEquals(KeyType.AES, storedKey.descriptor().type());
        assertEquals(AlgorithmId.AES_GCM, storedKey.descriptor().algorithm());
        assertEquals(256, storedKey.descriptor().keyBits());
        assertEquals(KeyState.ACTIVE, storedKey.descriptor().state());
        assertEquals(Set.of(ENCRYPT, DECRYPT), storedKey.descriptor().usages());
        assertEquals("default", storedKey.descriptor().tenantId());
        assertNotNull(storedKey.descriptor().fingerprint());
        assertTrue(storedKey.descriptor().rotationPolicy() == null);

        assertTrue(provider.load(KeyId.of("DEMO_AES"), KeyVersion.of(2)).isEmpty());

        StoredKey hmac = provider.load(KeyId.of("DEMO_HMAC"), KeyVersion.of(2)).orElseThrow();
        assertEquals(KeyType.HMAC, hmac.descriptor().type());
        assertEquals(AlgorithmId.HMAC_SHA256, hmac.descriptor().algorithm());
        assertEquals(Set.of(MAC), hmac.descriptor().usages());
        assertEquals(160, hmac.descriptor().keyBits());
        assertArrayEquals(HMAC_MATERIAL, hmac.material());
    }

    @Test
    void listsAvailableVariablesAndIsReadOnly() {
        List<StoredKey> records = provider.list(null);
        assertEquals(2, records.size());
        assertEquals("DEMO_AES", records.get(0).descriptor().keyId().value());
        assertEquals("DEMO_HMAC", records.get(1).descriptor().keyId().value());
        assertEquals(2, provider.list("default").size());
        assertEquals(0, provider.list("acme").size());

        KeyException save = assertThrows(KeyException.class,
                () -> provider.save(records.get(0)));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, save.errorCode());
        KeyException delete = assertThrows(KeyException.class,
                () -> provider.delete(KeyId.of("DEMO_AES"), KeyVersion.first()));
        assertEquals(ErrorCode.UNSUPPORTED_OPERATION, delete.errorCode());
        assertEquals(HealthStatus.UP, provider.health());
        assertEquals("environment", provider.providerId());
        provider.close();
    }

    @Test
    void rejectsCorruptBase64WithoutLeakingIt() {
        KeyException corrupt = assertThrows(KeyException.class,
                () -> provider.load(KeyId.of("CORRUPT"), KeyVersion.first()));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, corrupt.errorCode());
        assertFalse(corrupt.getMessage().contains("%%%"));
        assertFalse(corrupt.getMessage().contains("not-base64"));

        EnvironmentKeyProvider real = new EnvironmentKeyProvider(
                EnvironmentKeyProvider.DEFAULT_PREFIX);
        assertEquals(HealthStatus.UP, real.health());
    }

    @Test
    void managerCannotWriteToReadOnlyEnvironmentProvider() {
        DefaultKeyManager manager = new DefaultKeyManager(provider, List.of(),
                new StubPolicyEngine(), new RecordingAuditTrail(),
                new MutableClock(Instant.parse("2026-01-01T00:00:00Z")));
        KeyException failure = assertThrows(KeyException.class, () -> manager.generate(
                KeyGenerationRequest.builder(KeyType.AES, AlgorithmId.AES_GCM, Set.of(ENCRYPT))
                        .build(), CALLER));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, failure.errorCode());
        manager.close();
    }

    private static byte[] material(int length, int seed) {
        byte[] material = new byte[length];
        for (int i = 0; i < length; i++) {
            material[i] = (byte) (seed + i);
        }
        return material;
    }
}