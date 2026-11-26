package cn.tolim.spissatus4j.key.provider;

import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import cn.tolim.spissatus4j.contract.spi.StoredKey;
import cn.tolim.spissatus4j.key.internal.KeyRecordCodec;
import cn.tolim.spissatus4j.key.internal.KeySupport;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * File-backed key provider with authenticated encryption at rest.
 *
 * <p>Each (key id, version) record is a single {@code .spk} file named with
 * the lower-case SHA-256 fingerprint of the UTF-8 key id and the version, so
 * names are portable to case-insensitive file systems. Two record formats exist:</p>
 *
 * <pre>
 * v1: magic "SPS4KEY1" (8) | format version 1 (2) | salt (16) | nonce (12) |
 *     AES-256-GCM ciphertext + 128-bit tag
 * v2: magic "SPS4KEY1" (8) | format version 2 (2) | salt (16) |
 *     PBKDF2 iterations (4, big endian) | nonce (12) |
 *     AES-256-GCM ciphertext + 128-bit tag
 * </pre>
 *
 * <p>New records are written as v2 with PBKDF2-HMAC-SHA256 at 600000
 * iterations. Legacy v1 records (200000 iterations) remain readable; the next
 * save of such a record upgrades it to v2 while reusing the per-file random
 * salt. The magic, format version, salt and iteration count are authenticated
 * as additional data. Writes use a temporary file and an atomic move;
 * owner-only POSIX permissions are applied when the file system supports
 * them.</p>
 *
 * <p>All record access is serialized per provider instance and across
 * processes through an OS file lock on {@code <directory>/.spissatus.lock}.
 * Saves are conditional: terminal tombstones can never be overwritten and a
 * non-terminal record can never be turned into ACTIVE unless that transition
 * is a legal lifecycle transition. This keeps a stale writer from
 * resurrecting destroyed or revoked keys.</p>
 *
 * <p>The master password is never logged and is cleared when the provider is
 * closed. No plaintext key material is ever written.</p>
 */
public final class FileKeyProvider implements KeyProvider {

    public static final String PROVIDER_ID = "file";
    public static final String LOCK_FILE_NAME = ".spissatus.lock";

    private static final byte[] MAGIC = "SPS4KEY1".getBytes(StandardCharsets.US_ASCII);
    private static final short FORMAT_VERSION = 2;
    private static final short LEGACY_FORMAT_VERSION = 1;
    private static final int SALT_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH = 16;
    private static final int ITERATION_FIELD_LENGTH = 4;
    private static final int AAD_LENGTH_V1 = MAGIC.length + 2 + SALT_LENGTH;
    private static final int AAD_LENGTH_V2 = AAD_LENGTH_V1 + ITERATION_FIELD_LENGTH;
    private static final int HEADER_LENGTH_V1 = AAD_LENGTH_V1 + NONCE_LENGTH;
    private static final int HEADER_LENGTH_V2 = AAD_LENGTH_V2 + NONCE_LENGTH;
    private static final int ITERATIONS = 600_000;
    private static final int LEGACY_ITERATIONS = 200_000;
    private static final int MAX_ITERATIONS = 10_000_000;
    private static final int KEY_BITS = 256;
    private static final long MAX_RECORD_BYTES = 64L * 1024 * 1024;
    private static final Pattern FILE_NAME = Pattern.compile("^([0-9a-f]{64})-v(\\d+)\\.spk$");

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Process-wide monitors keyed by lock file. Java throws
     * {@link OverlappingFileLockException} when the same JVM tries to acquire
     * overlapping OS locks through different channels, so provider instances
     * in one process must first serialize on this monitor.
     */
    private static final ConcurrentHashMap<Path, Object> JVM_LOCKS = new ConcurrentHashMap<>();

    private final Path directory;
    private final Path lockFile;
    private final Object jvmLock;
    private final char[] masterPassword;
    private final Object lock = new Object();

    private byte[] cachedSalt;
    private SecretKey cachedKey;
    private int cachedIterations;
    private boolean closed;

    public FileKeyProvider(Path directory, char[] masterPassword) {
        this.directory = Objects.requireNonNull(directory, "directory").toAbsolutePath().normalize();
        if (masterPassword == null || masterPassword.length == 0) {
            throw new KeyException(ErrorCode.CONFIGURATION_INVALID,
                    "A master password is required for the file key provider");
        }
        this.masterPassword = masterPassword.clone();
        this.lockFile = this.directory.resolve(LOCK_FILE_NAME);
        this.jvmLock = JVM_LOCKS.computeIfAbsent(lockFile, ignored -> new Object());
        try {
            Files.createDirectories(this.directory);
        } catch (IOException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                    "Key storage directory could not be created");
        }
    }

    @Override
    public String providerId() {
        return PROVIDER_ID;
    }

    @Override
    public Optional<StoredKey> load(KeyId keyId, KeyVersion version) {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(version, "version");
        return withRecordLock(() -> {
            Path file = fileFor(keyId, version);
            if (!Files.exists(file)) {
                return Optional.empty();
            }
            StoredKey storedKey = readRecord(file);
            if (!storedKey.descriptor().keyId().equals(keyId)
                    || !storedKey.descriptor().version().equals(version)) {
                throw providerFailure("Key record does not match its file name");
            }
            return Optional.of(storedKey);
        });
    }

    @Override
    public void save(StoredKey storedKey) {
        Objects.requireNonNull(storedKey, "storedKey");
        withRecordLock(() -> {
            KeyId keyId = storedKey.descriptor().keyId();
            KeyVersion version = storedKey.descriptor().version();
            Path file = fileFor(keyId, version);

            byte[] material = storedKey.material();
            byte[] payload = null;
            try {
                if (material.length > KeyRecordCodec.MAX_MATERIAL_BYTES) {
                    throw new KeyException(ErrorCode.INVALID_PARAMETER,
                            "Key material exceeds the maximum supported size");
                }
                if (material.length == 0 && !storedKey.descriptor().state().terminal()) {
                    throw new KeyException(ErrorCode.INVALID_PARAMETER,
                            "Only a destroyed key record may have empty material");
                }
                enforceSavePrecondition(file, storedKey);
                payload = KeyRecordCodec.encodeStoredKey(storedKey.descriptor(), material,
                        storedKey.materialFormat(), true, storedKey.attributes());
                if (payload.length > MAX_RECORD_BYTES - HEADER_LENGTH_V2 - TAG_LENGTH) {
                    throw new KeyException(ErrorCode.INVALID_PARAMETER,
                            "Key record exceeds the maximum supported size");
                }
                byte[] salt = readExistingSalt(file)
                        .orElseGet(() -> KeySupport.randomBytes(SALT_LENGTH));
                SecretKey key = deriveKey(salt, ITERATIONS);
                byte[] nonce = KeySupport.randomBytes(NONCE_LENGTH);
                byte[] aad = aadV2(salt, ITERATIONS);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH * 8, nonce));
                cipher.updateAAD(aad);
                byte[] ciphertext = cipher.doFinal(payload);
                ByteBuffer output = ByteBuffer.allocate(HEADER_LENGTH_V2 + ciphertext.length);
                output.put(MAGIC).putShort(FORMAT_VERSION).put(salt).putInt(ITERATIONS)
                        .put(nonce).put(ciphertext);
                atomicWrite(file, output.array());
            } catch (GeneralSecurityException e) {
                throw providerFailure("Key record could not be written");
            } finally {
                Arrays.fill(material, (byte) 0);
                if (payload != null) {
                    Arrays.fill(payload, (byte) 0);
                }
            }
            return null;
        });
    }

    @Override
    public boolean delete(KeyId keyId, KeyVersion version) {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(version, "version");
        return withRecordLock(() -> {
            try {
                return Files.deleteIfExists(fileFor(keyId, version));
            } catch (IOException e) {
                throw providerFailure("Key record could not be deleted");
            }
        });
    }

    @Override
    public List<StoredKey> list(String tenantId) {
        return withRecordLock(() -> {
            List<StoredKey> result = new ArrayList<>();
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory, "*.spk")) {
                for (Path file : stream) {
                    String name = file.getFileName().toString();
                    Matcher matcher = FILE_NAME.matcher(name);
                    if (!matcher.matches()) {
                        continue;
                    }
                    KeyVersion version;
                    try {
                        version = new KeyVersion(Long.parseLong(matcher.group(2)));
                    } catch (IllegalArgumentException e) {
                        continue;
                    }
                    StoredKey storedKey = readRecord(file);
                    String expectedHash = KeySupport.fingerprint(
                            storedKey.descriptor().keyId().value()
                                    .getBytes(StandardCharsets.UTF_8));
                    if (!expectedHash.equals(matcher.group(1))
                            || !storedKey.descriptor().version().equals(version)) {
                        throw providerFailure("Key record does not match its file name");
                    }
                    KeyId keyId = storedKey.descriptor().keyId();
                    if (tenantId == null || tenantId.equals(storedKey.descriptor().tenantId())) {
                        result.add(storedKey);
                    }
                }
            } catch (IOException e) {
                throw providerFailure("Key storage directory could not be read");
            }
            result.sort(Comparator.comparing((StoredKey key) -> key.descriptor().keyId().value())
                    .thenComparingLong(key -> key.descriptor().version().value()));
            return List.copyOf(result);
        });
    }

    @Override
    public HealthStatus health() {
        synchronized (lock) {
            if (closed) {
                return HealthStatus.DOWN;
            }
            if (!Files.isDirectory(directory) || !Files.isReadable(directory)
                    || !Files.isWritable(directory)) {
                return HealthStatus.DOWN;
            }
            return HealthStatus.UP;
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            if (closed) {
                return;
            }
            closed = true;
            Arrays.fill(masterPassword, '\0');
            if (cachedSalt != null) {
                Arrays.fill(cachedSalt, (byte) 0);
            }
            cachedSalt = null;
            if (cachedKey != null) {
                byte[] encoded = cachedKey.getEncoded();
                if (encoded != null) {
                    Arrays.fill(encoded, (byte) 0);
                }
                cachedKey = null;
            }
            cachedIterations = 0;
        }
    }

    private <T> T withRecordLock(Supplier<T> action) {
        synchronized (jvmLock) {
            try (FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE);
                 FileLock fileLock = channel.lock()) {
                if (!fileLock.isValid()) {
                    throw providerFailure("Key storage lock could not be acquired");
                }
                applyOwnerOnly(lockFile);
                synchronized (lock) {
                    requireOpen();
                    return action.get();
                }
            } catch (IOException e) {
                throw providerFailure("Key storage lock could not be acquired");
            } catch (OverlappingFileLockException e) {
                throw providerFailure("Key storage lock could not be acquired");
            }
        }
    }

    /**
     * Rejects stale writes that would downgrade a record's lifecycle state or
     * resurrect a destroyed key. A terminal record is immutable; a
     * REVOKED or COMPROMISED record can never be overwritten as ACTIVE by a
     * stale provider save; DEACTIVATED -> ACTIVE remains a legal explicit
     * reactivation.
     */
    private void enforceSavePrecondition(Path file, StoredKey incoming) {
        if (!Files.exists(file)) {
            return;
        }
        StoredKey existing = readRecord(file);
        KeyState from = existing.descriptor().state();
        KeyState to = incoming.descriptor().state();
        if (from.terminal()) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                    "A destroyed key record cannot be overwritten");
        }
        if (from == to) {
            if (from == KeyState.ACTIVE
                    && !Arrays.equals(existing.material(), incoming.material())) {
                throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                        "Key record material conflicts with the stored record");
            }
            return;
        }
        // DEACTIVATED -> ACTIVE is a legal, explicit reactivation. The remaining
        // protections still prevent terminal resurrection and illegal jumps.
        if (!KeySupport.canTransition(from, to)) {
            throw new KeyException(ErrorCode.ILLEGAL_KEY_TRANSITION,
                    "Key record state transition is not permitted");
        }
    }

    private StoredKey readRecord(Path file) {
        byte[] bytes;
        try {
            long size = Files.size(file);
            if (size < HEADER_LENGTH_V1 + TAG_LENGTH || size > MAX_RECORD_BYTES) {
                throw providerFailure("Key record has an invalid size");
            }
            bytes = Files.readAllBytes(file);
        } catch (IOException e) {
            throw providerFailure("Key record could not be read");
        }
        try {
            if (bytes.length < MAGIC.length + 2
                    || !Arrays.equals(Arrays.copyOfRange(bytes, 0, MAGIC.length), MAGIC)) {
                throw providerFailure("Key record has an unsupported format");
            }
            short version = ByteBuffer.wrap(bytes, MAGIC.length, 2).getShort();
            ParsedHeader header = parseHeader(bytes, version);
            byte[] ciphertext = Arrays.copyOfRange(bytes, header.headerLength(), bytes.length);
            SecretKey key = deriveKey(header.salt(), header.iterations());
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key,
                    new GCMParameterSpec(TAG_LENGTH * 8, header.nonce()));
            cipher.updateAAD(header.aad());
            byte[] payload;
            try {
                payload = cipher.doFinal(ciphertext);
            } catch (GeneralSecurityException e) {
                throw providerFailure("Key record could not be decrypted");
            }
            try {
                return KeyRecordCodec.decodeStoredKey(payload);
            } finally {
                Arrays.fill(payload, (byte) 0);
            }
        } catch (GeneralSecurityException e) {
            throw providerFailure("Key record could not be decrypted");
        }
    }

    private ParsedHeader parseHeader(byte[] bytes, short version) {
        int saltOffset = MAGIC.length + 2;
        if (version == LEGACY_FORMAT_VERSION) {
            if (bytes.length < HEADER_LENGTH_V1 + TAG_LENGTH) {
                throw providerFailure("Key record has an invalid size");
            }
            byte[] salt = Arrays.copyOfRange(bytes, saltOffset, saltOffset + SALT_LENGTH);
            byte[] nonce = Arrays.copyOfRange(bytes, AAD_LENGTH_V1, AAD_LENGTH_V1 + NONCE_LENGTH);
            byte[] aad = Arrays.copyOfRange(bytes, 0, AAD_LENGTH_V1);
            return new ParsedHeader(salt, LEGACY_ITERATIONS, nonce, aad, HEADER_LENGTH_V1);
        }
        if (version == FORMAT_VERSION) {
            if (bytes.length < HEADER_LENGTH_V2 + TAG_LENGTH) {
                throw providerFailure("Key record has an invalid size");
            }
            int iterations = ByteBuffer.wrap(bytes, AAD_LENGTH_V1, ITERATION_FIELD_LENGTH).getInt();
            if (iterations < 1 || iterations > MAX_ITERATIONS) {
                throw providerFailure("Key record has an unsupported format");
            }
            byte[] salt = Arrays.copyOfRange(bytes, saltOffset, saltOffset + SALT_LENGTH);
            byte[] nonce = Arrays.copyOfRange(bytes, AAD_LENGTH_V2, AAD_LENGTH_V2 + NONCE_LENGTH);
            byte[] aad = Arrays.copyOfRange(bytes, 0, AAD_LENGTH_V2);
            return new ParsedHeader(salt, iterations, nonce, aad, HEADER_LENGTH_V2);
        }
        throw providerFailure("Key record has an unsupported format");
    }

    private SecretKey deriveKey(byte[] salt, int iterations) {
        if (cachedKey != null && cachedSalt != null && cachedIterations == iterations
                && Arrays.equals(cachedSalt, salt)) {
            return cachedKey;
        }
        PBEKeySpec spec = new PBEKeySpec(masterPassword, salt, iterations, KEY_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] derived = factory.generateSecret(spec).getEncoded();
            try {
                SecretKey key = new SecretKeySpec(derived, "AES");
                if (cachedKey != null) {
                    byte[] old = cachedKey.getEncoded();
                    if (old != null) {
                        Arrays.fill(old, (byte) 0);
                    }
                }
                if (cachedSalt != null) {
                    Arrays.fill(cachedSalt, (byte) 0);
                }
                cachedSalt = salt.clone();
                cachedKey = key;
                cachedIterations = iterations;
                return key;
            } finally {
                Arrays.fill(derived, (byte) 0);
            }
        } catch (GeneralSecurityException e) {
            throw providerFailure("Key derivation failed");
        } finally {
            spec.clearPassword();
        }
    }

    private Optional<byte[]> readExistingSalt(Path file) {
        if (!Files.exists(file)) {
            return Optional.empty();
        }
        try {
            byte[] header = new byte[MAGIC.length + 2 + SALT_LENGTH];
            try (var input = Files.newInputStream(file)) {
                int read = input.readNBytes(header, 0, header.length);
                if (read != header.length) {
                    return Optional.empty();
                }
            }
            if (!Arrays.equals(Arrays.copyOfRange(header, 0, MAGIC.length), MAGIC)) {
                return Optional.empty();
            }
            short version = ByteBuffer.wrap(header, MAGIC.length, 2).getShort();
            if (version != LEGACY_FORMAT_VERSION && version != FORMAT_VERSION) {
                return Optional.empty();
            }
            return Optional.of(Arrays.copyOfRange(header, MAGIC.length + 2, header.length));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    private byte[] aadV2(byte[] salt, int iterations) {
        ByteBuffer buffer = ByteBuffer.allocate(AAD_LENGTH_V2);
        buffer.put(MAGIC).putShort(FORMAT_VERSION).put(salt).putInt(iterations);
        return buffer.array();
    }

    private void atomicWrite(Path target, byte[] content) {
        Path temporary = null;
        try {
            temporary = Files.createTempFile(directory, "sp4k-", ".tmp");
            Files.write(temporary, content, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING);
            applyOwnerOnly(temporary);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
            temporary = null;
        } catch (IOException e) {
            throw providerFailure("Key record could not be written");
        } finally {
            if (temporary != null) {
                try {
                    Files.deleteIfExists(temporary);
                } catch (IOException ignored) {
                    // best effort cleanup
                }
            }
        }
    }

    private static void applyOwnerOnly(Path path) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Non-POSIX file system: rely on the encrypted payload instead.
        }
    }

    private Path fileFor(KeyId keyId, KeyVersion version) {
        String encoded = KeySupport.fingerprint(
                keyId.value().getBytes(StandardCharsets.UTF_8));
        return directory.resolve(encoded + "-v" + version.value() + ".spk");
    }

    private void requireOpen() {
        if (closed) {
            throw providerFailure("Key provider is closed");
        }
    }

    private static KeyException providerFailure(String message) {
        return new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, message);
    }

    private record ParsedHeader(byte[] salt, int iterations, byte[] nonce, byte[] aad,
                                int headerLength) {
    }
}
