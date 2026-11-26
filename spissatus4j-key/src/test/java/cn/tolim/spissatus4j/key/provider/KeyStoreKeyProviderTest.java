package cn.tolim.spissatus4j.key.provider;

import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.DECRYPT;
import static cn.tolim.spissatus4j.contract.algorithm.KeyUsage.ENCRYPT;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.key.RotationPolicy;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.spi.StoredKey;
import cn.tolim.spissatus4j.key.internal.KeyMaterialCodec;
import cn.tolim.spissatus4j.key.internal.KeySupport;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeyStoreKeyProviderTest {

    private static final Instant CREATED = Instant.parse("2026-03-01T00:00:00Z");
    private static final char[] PASSWORD = "changeit".toCharArray();

    @TempDir
    Path directory;

    @Test
    void persistsSymmetricKeysAcrossInstancesWithoutPlaintextMetadata() throws Exception {
        Path keyStore = directory.resolve("keys.jks");
        KeyStoreKeyProvider provider = new KeyStoreKeyProvider(keyStore, PASSWORD);
        KeyId keyId = KeyId.of("store-key");
        byte[] material = material(32, 0x71);
        StoredKey record = storedKey(keyId, 1, material, KeyState.ACTIVE,
                KeyMaterialCodec.RAW);

        provider.save(record);

        assertTrue(Files.exists(keyStore));
        assertFalse(Files.exists(directory.resolve("keystore.meta.properties")),
                "the unauthenticated sidecar must be gone");
        byte[] rawStore = Files.readAllBytes(keyStore);
        String rawText = new String(rawStore, StandardCharsets.ISO_8859_1);
        assertFalse(rawText.contains(Base64.getEncoder().encodeToString(material)),
                "the plaintext key must not appear in the keystore bytes");
        assertFalse(rawText.contains("\"tenantId\""),
                "descriptor metadata must not be stored in plaintext");

        StoredKey loaded = provider.load(keyId, KeyVersion.first()).orElseThrow();
        assertArrayEquals(material, loaded.material());
        assertTrue(loaded.encrypted());
        assertEquals(KeyMaterialCodec.RAW, loaded.materialFormat());
        assertEquals(record.descriptor(), loaded.descriptor());
        assertEquals(1, provider.list(null).size());
        assertEquals(HealthStatus.UP, provider.health());

        KeyStore store = openStore(keyStore);
        String alias = KeySupport.keyStoreAlias(keyId, KeyVersion.first());
        assertTrue(store.containsAlias(alias));
        assertTrue(store.containsAlias(KeyStoreKeyProvider.METADATA_ALIAS_PREFIX + alias));
        assertThrows(GeneralSecurityException.class, () -> store.getEntry(
                KeyStoreKeyProvider.METADATA_ALIAS_PREFIX + alias,
                new KeyStore.PasswordProtection("wrong-password".toCharArray())));

        KeyStore wrong = KeyStore.getInstance("JCEKS");
        assertThrows(IOException.class, () -> {
            try (InputStream input = Files.newInputStream(keyStore)) {
                wrong.load(input, "not-the-password".toCharArray());
            }
        });

        KeyStoreKeyProvider reopened = new KeyStoreKeyProvider(keyStore, PASSWORD);
        assertArrayEquals(material,
                reopened.load(keyId, KeyVersion.first()).orElseThrow().material());
        reopened.close();
        provider.close();
    }

    @Test
    void rejectsWrongPasswordAndTamperedInStoreMetadata() throws Exception {
        Path keyStore = directory.resolve("wrong-password.jks");
        KeyStoreKeyProvider provider = new KeyStoreKeyProvider(keyStore, PASSWORD);
        KeyId keyId = KeyId.of("secret-key");
        provider.save(storedKey(keyId, 1, material(24, 0x72), KeyState.ACTIVE,
                KeyMaterialCodec.RAW));

        KeyStoreKeyProvider wrong = new KeyStoreKeyProvider(keyStore,
                "not-the-password".toCharArray());
        KeyException failure = assertThrows(KeyException.class,
                () -> wrong.load(keyId, KeyVersion.first()));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, failure.errorCode());
        assertFalse(failure.getMessage().contains("not-the-password"));
        assertEquals(HealthStatus.DOWN, wrong.health());

        KeyStore store = openStore(keyStore);
        String alias = KeySupport.keyStoreAlias(keyId, KeyVersion.first());
        store.setEntry(KeyStoreKeyProvider.METADATA_ALIAS_PREFIX + alias,
                new KeyStore.SecretKeyEntry(new SecretKeySpec(
                        "{\"tampered\":true}".getBytes(StandardCharsets.UTF_8), "RAW")),
                new KeyStore.PasswordProtection(PASSWORD));
        try (OutputStream output = Files.newOutputStream(keyStore)) {
            store.store(output, PASSWORD);
        }

        KeyException tampered = assertThrows(KeyException.class,
                () -> provider.load(keyId, KeyVersion.first()));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, tampered.errorCode());
        assertFalse(tampered.getMessage().contains("tampered"));

        wrong.close();
        provider.close();
    }

    @Test
    void uppercaseKeyIdsAndMetadataPrefixLikeIdsDoNotCollide() {
        Path keyStore = directory.resolve("case.jks");
        KeyStoreKeyProvider provider = new KeyStoreKeyProvider(keyStore, PASSWORD);
        KeyId uppercase = KeyId.of("Case-Sensitive-Key");
        KeyId victim = KeyId.of("victim");
        KeyId prefixed = KeyId.of("spissatus-meta-victim");
        provider.save(storedKey(uppercase, 1, material(16, 0x81), KeyState.ACTIVE,
                KeyMaterialCodec.RAW));
        provider.save(storedKey(victim, 1, material(16, 0x82), KeyState.ACTIVE,
                KeyMaterialCodec.RAW));
        provider.save(storedKey(prefixed, 1, material(16, 0x83), KeyState.ACTIVE,
                KeyMaterialCodec.RAW));

        assertArrayEquals(material(16, 0x81), provider.load(uppercase,
                KeyVersion.first()).orElseThrow().material());
        assertArrayEquals(material(16, 0x82), provider.load(victim,
                KeyVersion.first()).orElseThrow().material());
        assertArrayEquals(material(16, 0x83), provider.load(prefixed,
                KeyVersion.first()).orElseThrow().material());
        assertEquals(3, provider.list(null).size());
        assertTrue(provider.delete(uppercase, KeyVersion.first()));
        provider.close();

        KeyStoreKeyProvider reopened = new KeyStoreKeyProvider(keyStore, PASSWORD);
        assertTrue(reopened.load(uppercase, KeyVersion.first()).isEmpty());
        assertArrayEquals(material(16, 0x82), reopened.load(victim,
                KeyVersion.first()).orElseThrow().material());
        reopened.close();
    }

    @Test
    void storesAndReadsDestroyedTombstonesAndDeletesBothEntries() throws Exception {
        Path keyStore = directory.resolve("tombstone.jks");
        KeyStoreKeyProvider provider = new KeyStoreKeyProvider(keyStore, PASSWORD);
        KeyId keyId = KeyId.of("tombstone-key");
        provider.save(storedKey(keyId, 1, material(16, 0x73), KeyState.ACTIVE,
                KeyMaterialCodec.RAW));

        provider.save(storedKey(keyId, 1, new byte[0], KeyState.DESTROYED,
                KeyMaterialCodec.RAW));

        StoredKey tombstone = provider.load(keyId, KeyVersion.first()).orElseThrow();
        assertEquals(KeyState.DESTROYED, tombstone.descriptor().state());
        assertEquals(0, tombstone.material().length);
        assertEquals(1, provider.list(null).size());

        String alias = KeySupport.keyStoreAlias(keyId, KeyVersion.first());
        KeyStore store = openStore(keyStore);
        assertFalse(store.containsAlias(alias), "tombstones must not keep key material");
        assertTrue(store.containsAlias(KeyStoreKeyProvider.METADATA_ALIAS_PREFIX + alias));

        assertTrue(provider.delete(keyId, KeyVersion.first()));
        KeyStore afterDelete = openStore(keyStore);
        assertFalse(afterDelete.containsAlias(alias));
        assertFalse(afterDelete.containsAlias(KeyStoreKeyProvider.METADATA_ALIAS_PREFIX + alias));
        assertTrue(provider.load(keyId, KeyVersion.first()).isEmpty());
        assertFalse(provider.delete(keyId, KeyVersion.first()));
        provider.close();
    }

    @Test
    void supportsMultipleVersionsAndTenantFiltering() {
        Path keyStore = directory.resolve("versions.jks");
        KeyStoreKeyProvider provider = new KeyStoreKeyProvider(keyStore, PASSWORD);
        KeyId keyId = KeyId.of("multi-version");
        provider.save(storedKey(keyId, 1, material(16, 0x74), KeyState.DEACTIVATED,
                KeyMaterialCodec.RAW));
        provider.save(storedKey(keyId, 2, material(16, 0x75), KeyState.ACTIVE,
                KeyMaterialCodec.RAW));

        List<StoredKey> records = provider.list(null);
        assertEquals(2, records.size());
        assertEquals(1, records.get(0).descriptor().version().value());
        assertEquals(2, records.get(1).descriptor().version().value());
        assertEquals(1, provider.load(keyId, KeyVersion.of(1)).orElseThrow()
                .descriptor().version().value());
        assertEquals(2, provider.list("default").size());
        assertEquals(0, provider.list("other").size());
        provider.close();
    }

    @Test
    void metadataIsScopedToItsKeyStore() {
        Path firstStore = directory.resolve("first.jks");
        Path secondStore = directory.resolve("second.jks");
        KeyStoreKeyProvider first = new KeyStoreKeyProvider(firstStore, PASSWORD);
        KeyStoreKeyProvider second = new KeyStoreKeyProvider(secondStore, PASSWORD);
        KeyId keyId = KeyId.of("shared-alias");
        first.save(storedKeyForTenant(keyId, "tenant-a"));
        second.save(storedKeyForTenant(keyId, "tenant-b"));

        assertEquals("tenant-a", first.load(keyId, KeyVersion.first()).orElseThrow()
                .descriptor().tenantId());
        assertEquals("tenant-b", second.load(keyId, KeyVersion.first()).orElseThrow()
                .descriptor().tenantId());
        first.close();
        second.close();
    }

    @Test
    void legacyMaterialEntryWithoutMetadataFailsClosed() throws Exception {
        Path keyStore = directory.resolve("legacy.jks");
        byte[] material = material(16, 0x76);
        KeyStore store = KeyStore.getInstance("JCEKS");
        store.load(null, PASSWORD);
        KeyId legacyId = KeyId.of("legacy");
        store.setEntry(KeySupport.keyStoreAlias(legacyId, KeyVersion.first()),
                new KeyStore.SecretKeyEntry(new SecretKeySpec(material, "RAW")),
                new KeyStore.PasswordProtection(PASSWORD));
        try (OutputStream output = Files.newOutputStream(keyStore)) {
            store.store(output, PASSWORD);
        }

        KeyStoreKeyProvider provider = new KeyStoreKeyProvider(keyStore, PASSWORD);
        KeyException failure = assertThrows(KeyException.class,
                () -> provider.load(legacyId, KeyVersion.first()));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, failure.errorCode());
        assertTrue(provider.list(null).isEmpty(),
                "entries without authenticated metadata must not be listed");
        provider.close();
    }

    private static KeyStore openStore(Path keyStore) throws Exception {
        KeyStore store = KeyStore.getInstance("JCEKS");
        try (InputStream input = Files.newInputStream(keyStore)) {
            store.load(input, PASSWORD);
        }
        return store;
    }

    private static StoredKey storedKeyForTenant(KeyId keyId, String tenantId) {
        byte[] material = material(16, 0x77);
        KeyDescriptor descriptor = KeyDescriptor.builder()
                .keyId(keyId)
                .version(KeyVersion.first())
                .type(KeyType.AES)
                .algorithm(AlgorithmId.AES_GCM)
                .keyBits(128)
                .state(KeyState.ACTIVE)
                .usages(Set.of(ENCRYPT, DECRYPT))
                .tenantId(tenantId)
                .createdAt(CREATED)
                .activatedAt(CREATED)
                .rotationPolicy(RotationPolicy.defaults())
                .exportable(false)
                .usageCount(0)
                .attributes(Map.of())
                .fingerprint(KeySupport.fingerprint(material))
                .build();
        return new StoredKey(descriptor, material, KeyMaterialCodec.RAW, false, Map.of());
    }

    private static StoredKey storedKey(KeyId keyId, long version, byte[] material,
                                       KeyState state, String format) {
        KeyDescriptor descriptor = KeyDescriptor.builder()
                .keyId(keyId)
                .version(KeyVersion.of(version))
                .type(KeyType.AES)
                .algorithm(AlgorithmId.AES_GCM)
                .keyBits(material.length == 0 ? 256 : material.length * 8)
                .state(state)
                .usages(Set.of(ENCRYPT, DECRYPT))
                .tenantId("default")
                .createdAt(CREATED)
                .activatedAt(CREATED)
                .rotationPolicy(RotationPolicy.defaults())
                .exportable(false)
                .usageCount(0)
                .attributes(Map.of())
                .fingerprint(material.length == 0 ? null : KeySupport.fingerprint(material))
                .build();
        return new StoredKey(descriptor, material, format, false, Map.of());
    }

    private static byte[] material(int length, int seed) {
        byte[] material = new byte[length];
        for (int i = 0; i < length; i++) {
            material[i] = (byte) (seed + i);
        }
        return material;
    }
}
