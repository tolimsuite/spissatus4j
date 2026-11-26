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
import cn.tolim.spissatus4j.key.internal.KeyRecordCodec;
import cn.tolim.spissatus4j.key.internal.KeySupport;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileKeyProviderTest {

    private static final Instant CREATED = Instant.parse("2026-02-01T00:00:00Z");
    private static final char[] PASSWORD = "correct-horse-battery".toCharArray();
    private static final byte[] MAGIC = "SPS4KEY1".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path directory;

    @Test
    void persistsEncryptedRecordsAcrossInstances() throws IOException {
        FileKeyProvider provider = new FileKeyProvider(directory, PASSWORD);
        KeyId keyId = KeyId.of("file-key");
        byte[] material = material(32, 0x11);
        StoredKey record = storedKey(keyId, 1, material, KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of("origin", "test"));

        provider.save(record);

        Path file = providerFile(keyId, 1);
        assertTrue(Files.exists(file));
        assertTrue(file.getFileName().toString().endsWith(".spk"));
        byte[] bytes = Files.readAllBytes(file);
        assertFalse(contains(bytes, material), "the raw key must never appear in the file");

        StoredKey loaded = provider.load(keyId, KeyVersion.first()).orElseThrow();
        assertArrayEquals(material, loaded.material());
        assertTrue(loaded.encrypted());
        assertEquals(KeyMaterialCodec.RAW, loaded.materialFormat());
        assertEquals("test", loaded.attributes().get("origin"));
        assertEquals(record.descriptor(), loaded.descriptor());

        FileKeyProvider reopened = new FileKeyProvider(directory, PASSWORD);
        StoredKey reloaded = reopened.load(keyId, KeyVersion.first()).orElseThrow();
        assertArrayEquals(material, reloaded.material());
        assertEquals(1, reopened.list(null).size());
        assertEquals(0, reopened.list("acme").size());
        assertEquals(HealthStatus.UP, reopened.health());
        reopened.close();
        provider.close();
    }

    @Test
    void readsOwnTombstonesAfterReopenWithoutBreakingOtherKeys() {
        FileKeyProvider provider = new FileKeyProvider(directory, PASSWORD);
        KeyId destroyedId = KeyId.of("destroyed-file");
        KeyId liveId = KeyId.of("live-file");
        byte[] destroyedMaterial = material(32, 0x12);
        byte[] liveMaterial = material(32, 0x13);
        provider.save(storedKey(destroyedId, 1, destroyedMaterial, KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of()));
        provider.save(storedKey(liveId, 1, liveMaterial, KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of()));
        provider.save(storedKey(destroyedId, 1, new byte[0], KeyState.DESTROYED,
                KeyMaterialCodec.RAW, Map.of()));
        provider.close();

        FileKeyProvider reopened = new FileKeyProvider(directory, PASSWORD);
        StoredKey tombstone = reopened.load(destroyedId, KeyVersion.first()).orElseThrow();
        assertEquals(KeyState.DESTROYED, tombstone.descriptor().state());
        assertEquals(0, tombstone.material().length);
        assertEquals(2, reopened.list(null).size());
        assertArrayEquals(liveMaterial,
                reopened.load(liveId, KeyVersion.first()).orElseThrow().material());
        reopened.close();
    }

    @Test
    void rejectsWrongPasswordAndTamperedRecords() throws IOException {
        FileKeyProvider provider = new FileKeyProvider(directory, PASSWORD);
        KeyId keyId = KeyId.of("secret-file");
        byte[] material = material(32, 0x22);
        provider.save(storedKey(keyId, 1, material, KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of()));

        FileKeyProvider wrongPassword = new FileKeyProvider(directory,
                "definitely-not-it".toCharArray());
        KeyException wrong = assertThrows(KeyException.class,
                () -> wrongPassword.load(keyId, KeyVersion.first()));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, wrong.errorCode());
        assertFalse(wrong.getMessage().contains("definitely-not-it"));
        assertFalse(wrong.getMessage().contains("wrong"));
        for (KeyException exception : List.of(wrong)) {
            assertFalse(exception.getMessage().contains(java.util.Base64.getEncoder()
                    .encodeToString(material)));
        }

        Path file = providerFile(keyId, 1);
        byte[] bytes = Files.readAllBytes(file);
        bytes[bytes.length - 1] ^= 0x01;
        Files.write(file, bytes);
        KeyException tampered = assertThrows(KeyException.class,
                () -> provider.load(keyId, KeyVersion.first()));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, tampered.errorCode());
        assertFalse(tampered.getMessage().contains("GCM"));

        provider.close();
        wrongPassword.close();
    }

    @Test
    void supportsListingDeletionAndAtomicOwnerOnlyWrites() throws IOException {
        FileKeyProvider provider = new FileKeyProvider(directory, PASSWORD);
        provider.save(storedKey(KeyId.of("file-a"), 1, material(16, 0x31), KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of()));
        provider.save(storedKey(KeyId.of("file-b"), 2, material(24, 0x32), KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of()));

        List<StoredKey> records = provider.list(null);
        assertEquals(2, records.size());
        assertEquals("file-a", records.get(0).descriptor().keyId().value());
        assertEquals("file-b", records.get(1).descriptor().keyId().value());
        assertEquals(2, provider.list("default").size());

        Path file = providerFile(KeyId.of("file-a"), 1);
        if (Files.getFileStore(file).supportsFileAttributeView(PosixFileAttributeView.class)) {
            assertEquals(PosixFilePermissions.fromString("rw-------"),
                    Files.getPosixFilePermissions(file));
        }

        assertTrue(provider.delete(KeyId.of("file-a"), KeyVersion.first()));
        assertFalse(provider.delete(KeyId.of("file-a"), KeyVersion.first()));
        assertTrue(provider.load(KeyId.of("file-a"), KeyVersion.first()).isEmpty());

        try (Stream<Path> files = Files.list(directory)) {
            assertFalse(files.anyMatch(path -> path.getFileName().toString().endsWith(".tmp")),
                    "temporary files must be moved or removed");
        }
        provider.close();
    }

    @Test
    void overwritesRecordsAtomicallyAndReusesSalt() throws IOException {
        FileKeyProvider provider = new FileKeyProvider(directory, PASSWORD);
        KeyId keyId = KeyId.of("rewritten-key");
        byte[] material = material(32, 0x45);
        StoredKey first = storedKey(keyId, 1, material, KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of());
        provider.save(first);
        Path file = providerFile(keyId, 1);
        byte[] firstBytes = Files.readAllBytes(file);
        byte[] firstSalt = Arrays.copyOfRange(firstBytes, 10, 26);

        KeyDescriptor updated = first.descriptor().withUsageCount(7);
        provider.save(new StoredKey(updated, material, KeyMaterialCodec.RAW, true, Map.of()));
        byte[] secondBytes = Files.readAllBytes(file);
        byte[] secondSalt = Arrays.copyOfRange(secondBytes, 10, 26);
        assertArrayEquals(firstSalt, secondSalt);
        assertFalse(Arrays.equals(firstBytes, secondBytes));
        assertEquals(7, provider.load(keyId, KeyVersion.first()).orElseThrow()
                .descriptor().usageCount());
        assertArrayEquals(material,
                provider.load(keyId, KeyVersion.first()).orElseThrow().material());
        provider.close();
    }

    @Test
    void rejectsMalformedHeadersAndClosedProvider() throws IOException {
        FileKeyProvider provider = new FileKeyProvider(directory, PASSWORD);
        KeyId keyId = KeyId.of("magic-check");
        provider.save(storedKey(keyId, 1, material(16, 0x41), KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of()));
        Path file = providerFile(keyId, 1);
        byte[] bytes = Files.readAllBytes(file);
        bytes[0] = 'X';
        Files.write(file, bytes);
        KeyException badMagic = assertThrows(KeyException.class,
                () -> provider.load(keyId, KeyVersion.first()));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, badMagic.errorCode());

        provider.close();
        assertEquals(HealthStatus.DOWN, provider.health());
        assertThrows(KeyException.class, () -> provider.load(keyId, KeyVersion.first()));
    }

    @Test
    void keyIdsDifferingOnlyByCaseGetDistinctRecordFiles() {
        FileKeyProvider provider = new FileKeyProvider(directory, PASSWORD);
        KeyId lower = KeyId.of("aaa");
        KeyId mixed = KeyId.of("aaG");
        provider.save(storedKey(lower, 1, material(16, 0x91), KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of()));
        provider.save(storedKey(mixed, 1, material(16, 0x92), KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of()));

        assertArrayEquals(material(16, 0x91),
                provider.load(lower, KeyVersion.first()).orElseThrow().material());
        assertArrayEquals(material(16, 0x92),
                provider.load(mixed, KeyVersion.first()).orElseThrow().material());
        assertEquals(2, provider.list(null).size());
        provider.close();
    }

    @Test
    void rejectsStaleSavesThatWouldResurrectDestroyedKeysButAllowsReactivation() {
        FileKeyProvider first = new FileKeyProvider(directory, PASSWORD);
        FileKeyProvider second = new FileKeyProvider(directory, PASSWORD);

        KeyId destroyedId = KeyId.of("stale-destroyed");
        StoredKey active = storedKey(destroyedId, 1, material(32, 0x51), KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of());
        first.save(active);
        first.save(storedKey(destroyedId, 1, new byte[0], KeyState.DESTROYED,
                KeyMaterialCodec.RAW, Map.of()));

        KeyException resurrect = assertThrows(KeyException.class, () -> second.save(active));
        assertTrue(resurrect.errorCode() == ErrorCode.KEY_PROVIDER_FAILURE
                || resurrect.errorCode() == ErrorCode.ILLEGAL_KEY_TRANSITION);
        assertEquals(KeyState.DESTROYED, second.load(destroyedId, KeyVersion.first())
                .orElseThrow().descriptor().state());

        KeyId deactivatedId = KeyId.of("legal-reactivation");
        StoredKey activeAgain = storedKey(deactivatedId, 1, material(32, 0x52), KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of());
        first.save(activeAgain);
        first.save(storedKey(deactivatedId, 1, material(32, 0x52), KeyState.DEACTIVATED,
                KeyMaterialCodec.RAW, Map.of()));
        second.save(activeAgain);
        assertEquals(KeyState.ACTIVE, second.load(deactivatedId, KeyVersion.first())
                .orElseThrow().descriptor().state(),
                "explicit DEACTIVATED -> ACTIVE reactivation remains legal");

        KeyId legalId = KeyId.of("legal-lifecycle");
        first.save(storedKey(legalId, 1, material(16, 0x53), KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of()));
        first.save(storedKey(legalId, 1, material(16, 0x53), KeyState.DEACTIVATED,
                KeyMaterialCodec.RAW, Map.of()));
        first.save(storedKey(legalId, 1, new byte[0], KeyState.DESTROYED,
                KeyMaterialCodec.RAW, Map.of()));
        assertEquals(KeyState.DESTROYED, first.load(legalId, KeyVersion.first())
                .orElseThrow().descriptor().state());

        first.close();
        second.close();
    }

    @Test
    void concurrentWritesFromTwoProvidersRemainReadable() throws Exception {
        FileKeyProvider first = new FileKeyProvider(directory, PASSWORD);
        FileKeyProvider second = new FileKeyProvider(directory, PASSWORD);
        int keysPerWriter = 3;
        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<?>> futures = new ArrayList<>();
            futures.add(pool.submit(() -> {
                await(start);
                for (int i = 0; i < keysPerWriter; i++) {
                    first.save(storedKey(KeyId.of("concurrent-a-" + i), 1,
                            material(16, 0x60 + i), KeyState.ACTIVE, KeyMaterialCodec.RAW,
                            Map.of()));
                }
            }));
            futures.add(pool.submit(() -> {
                await(start);
                for (int i = 0; i < keysPerWriter; i++) {
                    second.save(storedKey(KeyId.of("concurrent-b-" + i), 1,
                            material(16, 0x70 + i), KeyState.ACTIVE, KeyMaterialCodec.RAW,
                            Map.of()));
                }
            }));
            start.countDown();
            for (Future<?> future : futures) {
                future.get(60, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
            first.close();
            second.close();
        }

        FileKeyProvider reopened = new FileKeyProvider(directory, PASSWORD);
        assertEquals(keysPerWriter * 2, reopened.list(null).size());
        for (int i = 0; i < keysPerWriter; i++) {
            assertArrayEquals(material(16, 0x60 + i),
                    reopened.load(KeyId.of("concurrent-a-" + i), KeyVersion.first())
                            .orElseThrow().material());
            assertArrayEquals(material(16, 0x70 + i),
                    reopened.load(KeyId.of("concurrent-b-" + i), KeyVersion.first())
                            .orElseThrow().material());
        }
        reopened.close();
    }

    @Test
    void rejectsOversizedMaterialBeforeWritingAndKeepsExistingStoreReadable() {
        FileKeyProvider provider = new FileKeyProvider(directory, PASSWORD);
        KeyId existingId = KeyId.of("existing-key");
        byte[] existing = material(32, 0x61);
        provider.save(storedKey(existingId, 1, existing, KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of()));

        byte[] huge = new byte[KeyRecordCodec.MAX_MATERIAL_BYTES + 1];
        KeyException rejected = assertThrows(KeyException.class,
                () -> provider.save(storedKey(KeyId.of("huge-key"), 1, huge, KeyState.ACTIVE,
                        KeyMaterialCodec.RAW, Map.of())));
        assertEquals(ErrorCode.INVALID_PARAMETER, rejected.errorCode());
        assertFalse(Files.exists(recordPath(KeyId.of("huge-key"), 1)));

        assertArrayEquals(existing, provider.load(existingId, KeyVersion.first())
                .orElseThrow().material());
        assertEquals(1, provider.list(null).size());
        provider.close();
    }

    @Test
    void writesVersionTwoHeaderAndRecordsIterationCount() throws IOException {
        FileKeyProvider provider = new FileKeyProvider(directory, PASSWORD);
        KeyId keyId = KeyId.of("v2-key");
        provider.save(storedKey(keyId, 1, material(16, 0x62), KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of()));

        byte[] bytes = Files.readAllBytes(providerFile(keyId, 1));
        assertEquals(2, ByteBuffer.wrap(bytes, 8, 2).getShort());
        assertEquals(600_000, ByteBuffer.wrap(bytes, 26, 4).getInt());
        provider.close();
    }

    @Test
    void readsLegacyVersionOneRecordsAndUpgradesThemOnSave() throws Exception {
        KeyId keyId = KeyId.of("legacy-v1");
        byte[] material = material(32, 0x63);
        StoredKey legacy = storedKey(keyId, 1, material, KeyState.ACTIVE,
                KeyMaterialCodec.RAW, Map.of());
        writeLegacyV1Record(recordPath(keyId, 1), legacy);

        FileKeyProvider provider = new FileKeyProvider(directory, PASSWORD);
        StoredKey loaded = provider.load(keyId, KeyVersion.first()).orElseThrow();
        assertArrayEquals(material, loaded.material());
        assertEquals(KeyVersion.first(), loaded.descriptor().version());

        provider.save(new StoredKey(loaded.descriptor().withUsageCount(3), material,
                KeyMaterialCodec.RAW, true, Map.of()));
        byte[] upgraded = Files.readAllBytes(providerFile(keyId, 1));
        assertEquals(2, ByteBuffer.wrap(upgraded, 8, 2).getShort());
        assertEquals(600_000, ByteBuffer.wrap(upgraded, 26, 4).getInt());
        assertEquals(3, provider.load(keyId, KeyVersion.first()).orElseThrow()
                .descriptor().usageCount());
        provider.close();
    }

    private void writeLegacyV1Record(Path file, StoredKey key) throws Exception {
        byte[] payload = KeyRecordCodec.encodeStoredKey(key.descriptor(), key.material(),
                key.materialFormat(), true, key.attributes());
        byte[] salt = new byte[16];
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(salt);
        new SecureRandom().nextBytes(nonce);
        PBEKeySpec spec = new PBEKeySpec(PASSWORD, salt, 200_000, 256);
        SecretKey derived;
        try {
            derived = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec);
        } finally {
            spec.clearPassword();
        }
        ByteBuffer aad = ByteBuffer.allocate(26).put(MAGIC).putShort((short) 1).put(salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(derived.getEncoded(), "AES"),
                new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad.array());
        byte[] ciphertext = cipher.doFinal(payload);
        ByteBuffer record = ByteBuffer.allocate(38 + ciphertext.length)
                .put(aad.array()).put(nonce).put(ciphertext);
        Files.write(file, record.array());
    }

    private Path recordPath(KeyId keyId, long version) {
        return directory.resolve(KeySupport.fingerprint(
                keyId.value().getBytes(StandardCharsets.UTF_8)) + "-v" + version + ".spk");
    }

    private Path providerFile(KeyId keyId, long version) throws IOException {
        try (Stream<Path> files = Files.list(directory)) {
            return files.filter(path -> path.getFileName().toString().endsWith("-v"
                            + version + ".spk"))
                    .sorted(Comparator.comparing(Path::toString))
                    .findFirst()
                    .orElseThrow();
        }
    }

    private static StoredKey storedKey(KeyId keyId, long version, byte[] material,
                                       KeyState state, String format,
                                       Map<String, String> attributes) {
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
                .activatedAt(state == KeyState.PRE_ACTIVATION ? null : CREATED)
                .rotationPolicy(RotationPolicy.defaults())
                .exportable(false)
                .usageCount(0)
                .attributes(Map.of())
                .fingerprint(material.length == 0 ? null : KeySupport.fingerprint(material))
                .build();
        return new StoredKey(descriptor, material, format, false, attributes);
    }

    private static byte[] material(int length, int seed) {
        byte[] material = new byte[length];
        for (int i = 0; i < length; i++) {
            material[i] = (byte) (seed + i);
        }
        return material;
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
