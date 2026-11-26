package cn.tolim.spissatus4j.key.provider;

import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import cn.tolim.spissatus4j.contract.spi.StoredKey;
import cn.tolim.spissatus4j.key.internal.KeyRecordCodec;
import cn.tolim.spissatus4j.key.internal.KeyRecordCodec.Metadata;
import cn.tolim.spissatus4j.key.internal.KeySupport;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.crypto.spec.SecretKeySpec;

/**
 * Java KeyStore backed key provider.
 *
 * <p>Encoded material is stored as a SecretKeyEntry under the alias
 * {@code <keyId>-v<version>} protected by the keystore password. Non-secret
 * descriptor metadata is stored in the same keystore as a second,
 * password-protected SecretKeyEntry under the alias
 * {@code spissatus/meta/<hex-keyId>-v<version>} (the slash is not legal in a
 * KeyId, so metadata aliases cannot collide with material aliases). Both entries are written in one
 * store write, so metadata is authenticated by the keystore password and
 * cannot be read or altered without it. There is no plaintext sidecar file.</p>
 *
 * <p>The JDK's JKS implementation rejects secret-key entries, so the provider
 * uses the JCEKS format (a Java KeyStore that supports secret keys). Existing
 * JKS files can still be read, but cannot store new secret entries. Entries
 * without a matching authenticated metadata entry fail closed.</p>
 */
public final class KeyStoreKeyProvider implements KeyProvider {

    public static final String PROVIDER_ID = "keystore";
    public static final String METADATA_ALIAS_PREFIX = "spissatus/meta/";

    private static final String JCEKS = "JCEKS";
    private static final String JKS = "JKS";
    private static final byte[] JCEKS_MAGIC = {(byte) 0xce, (byte) 0xce, (byte) 0xce, (byte) 0xce};
    private static final byte[] JKS_MAGIC = {(byte) 0xfe, (byte) 0xed, (byte) 0xfe, (byte) 0xed};

    private final Path keyStoreFile;
    private final char[] password;
    private final Object lock = new Object();

    private boolean closed;

    public KeyStoreKeyProvider(Path keyStoreFile, char[] password) {
        this.keyStoreFile = Objects.requireNonNull(keyStoreFile, "keyStoreFile")
                .toAbsolutePath().normalize();
        if (password == null || password.length == 0) {
            throw new KeyException(ErrorCode.CONFIGURATION_INVALID,
                    "A keystore password is required");
        }
        this.password = password.clone();
        Path parent = this.keyStoreFile.getParent();
        try {
            if (parent != null) {
                Files.createDirectories(parent);
            }
        } catch (IOException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                    "Key store directory could not be created");
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
        synchronized (lock) {
            requireOpen();
            String alias = KeySupport.keyStoreAlias(keyId, version);
            KeyStore store = loadStore();
            KeyStore.Entry entry = entry(store, alias);
            Metadata metadata = readMetadata(store, metaAlias(alias));
            if (entry == null) {
                if (metadata == null) {
                    return Optional.empty();
                }
                validateMatch(metadata.descriptor(), keyId, version);
                if (metadata.descriptor().state().terminal()) {
                    return Optional.of(tombstone(metadata));
                }
                throw providerFailure("Key material is missing");
            }
            if (metadata == null) {
                throw providerFailure("Key metadata is missing");
            }
            validateMatch(metadata.descriptor(), keyId, version);
            if (metadata.descriptor().state().terminal()) {
                return Optional.of(tombstone(metadata));
            }
            if (!(entry instanceof KeyStore.SecretKeyEntry secretEntry)) {
                throw providerFailure("Key store entry has an unsupported type");
            }
            byte[] material = secretEntry.getSecretKey().getEncoded();
            if (material == null || material.length == 0) {
                throw providerFailure("Key material is unavailable");
            }
            verifyFingerprint(metadata.descriptor(), material);
            return Optional.of(new StoredKey(metadata.descriptor(), material,
                    metadata.materialFormat(), true, Map.of()));
        }
    }

    @Override
    public void save(StoredKey storedKey) {
        Objects.requireNonNull(storedKey, "storedKey");
        synchronized (lock) {
            requireOpen();
            KeyDescriptor descriptor = storedKey.descriptor();
            String alias = KeySupport.keyStoreAlias(descriptor.keyId(), descriptor.version());
            String metaAlias = metaAlias(alias);
            KeyStore store = loadStore();
            byte[] material = storedKey.material();
            byte[] metadataBytes = null;
            try {
                if (material.length > KeyRecordCodec.MAX_MATERIAL_BYTES) {
                    throw new KeyException(ErrorCode.INVALID_PARAMETER,
                            "Key material exceeds the maximum supported size");
                }
                if (material.length == 0) {
                    if (!descriptor.state().terminal()) {
                        throw new KeyException(ErrorCode.INVALID_PARAMETER,
                                "Only a destroyed key record may have empty material");
                    }
                    if (store.containsAlias(alias)) {
                        store.deleteEntry(alias);
                    }
                } else {
                    store.setEntry(alias,
                            new KeyStore.SecretKeyEntry(new SecretKeySpec(material, "RAW")),
                            new KeyStore.PasswordProtection(password));
                }
                metadataBytes = KeyRecordCodec.encodeMetadata(descriptor,
                        storedKey.materialFormat()).getBytes(StandardCharsets.UTF_8);
                store.setEntry(metaAlias,
                        new KeyStore.SecretKeyEntry(new SecretKeySpec(metadataBytes, "RAW")),
                        new KeyStore.PasswordProtection(password));
            } catch (GeneralSecurityException e) {
                throw providerFailure("Key store entry could not be written");
            } finally {
                Arrays.fill(material, (byte) 0);
                if (metadataBytes != null) {
                    Arrays.fill(metadataBytes, (byte) 0);
                }
            }
            writeStore(store);
        }
    }

    @Override
    public boolean delete(KeyId keyId, KeyVersion version) {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(version, "version");
        synchronized (lock) {
            requireOpen();
            String alias = KeySupport.keyStoreAlias(keyId, version);
            String metaAlias = metaAlias(alias);
            KeyStore store = loadStore();
            boolean present = false;
            try {
                if (store.containsAlias(alias)) {
                    store.deleteEntry(alias);
                    present = true;
                }
                if (store.containsAlias(metaAlias)) {
                    store.deleteEntry(metaAlias);
                    present = true;
                }
            } catch (GeneralSecurityException e) {
                throw providerFailure("Key store entry could not be deleted");
            }
            if (present) {
                writeStore(store);
            }
            return present;
        }
    }

    @Override
    public List<StoredKey> list(String tenantId) {
        synchronized (lock) {
            requireOpen();
            KeyStore store = loadStore();
            List<StoredKey> result = new ArrayList<>();
            try {
                Enumeration<String> aliases = store.aliases();
                while (aliases.hasMoreElements()) {
                    String metaAlias = aliases.nextElement();
                    if (!metaAlias.startsWith(METADATA_ALIAS_PREFIX)) {
                        continue;
                    }
                    String alias = metaAlias.substring(METADATA_ALIAS_PREFIX.length());
                    Metadata decoded = readMetadata(store, metaAlias);
                    if (decoded == null) {
                        continue;
                    }
                    KeyDescriptor descriptor = decoded.descriptor();
                    String expectedAlias = KeySupport.keyStoreAlias(descriptor.keyId(),
                            descriptor.version());
                    if (!expectedAlias.equals(alias)) {
                        throw providerFailure("Key metadata does not match its alias");
                    }
                    if (tenantId != null && !tenantId.equals(descriptor.tenantId())) {
                        continue;
                    }
                    if (descriptor.state().terminal()) {
                        result.add(tombstone(decoded));
                        continue;
                    }
                    KeyStore.Entry entry = entry(store, alias);
                    if (!(entry instanceof KeyStore.SecretKeyEntry secretEntry)) {
                        throw providerFailure("Key store entry is missing");
                    }
                    byte[] material = secretEntry.getSecretKey().getEncoded();
                    if (material == null || material.length == 0) {
                        throw providerFailure("Key material is unavailable");
                    }
                    verifyFingerprint(descriptor, material);
                    result.add(new StoredKey(descriptor, material, decoded.materialFormat(), true,
                            Map.of()));
                }
            } catch (GeneralSecurityException e) {
                throw providerFailure("Key store could not be read");
            }
            result.sort(Comparator.comparing((StoredKey key) -> key.descriptor().keyId().value())
                    .thenComparingLong(key -> key.descriptor().version().value()));
            return List.copyOf(result);
        }
    }

    @Override
    public HealthStatus health() {
        synchronized (lock) {
            if (closed) {
                return HealthStatus.DOWN;
            }
            if (!Files.exists(keyStoreFile)) {
                return HealthStatus.UP;
            }
            try {
                loadStore();
                return HealthStatus.UP;
            } catch (RuntimeException e) {
                return HealthStatus.DOWN;
            }
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            if (closed) {
                return;
            }
            closed = true;
            Arrays.fill(password, '\0');
        }
    }

    private KeyStore.Entry entry(KeyStore store, String alias) {
        try {
            return store.getEntry(alias, new KeyStore.PasswordProtection(password));
        } catch (GeneralSecurityException e) {
            throw providerFailure("Key store entry could not be read");
        }
    }

    private Metadata readMetadata(KeyStore store, String metaAlias) {
        KeyStore.Entry entry = entry(store, metaAlias);
        if (entry == null) {
            return null;
        }
        if (!(entry instanceof KeyStore.SecretKeyEntry secretEntry)) {
            throw providerFailure("Key metadata has an unsupported type");
        }
        byte[] encoded = secretEntry.getSecretKey().getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw providerFailure("Key metadata is unavailable");
        }
        try {
            return KeyRecordCodec.decodeMetadata(new String(encoded, StandardCharsets.UTF_8));
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private KeyStore loadStore() {
        String type = storeType();
        try {
            KeyStore store = KeyStore.getInstance(type);
            if (Files.exists(keyStoreFile)) {
                try (InputStream input = Files.newInputStream(keyStoreFile)) {
                    store.load(input, password);
                }
            } else {
                store.load(null, password);
            }
            return store;
        } catch (IOException | GeneralSecurityException e) {
            throw providerFailure("Key store could not be opened");
        }
    }

    private String storeType() {
        if (!Files.exists(keyStoreFile)) {
            return JCEKS;
        }
        byte[] magic = new byte[4];
        try (InputStream input = Files.newInputStream(keyStoreFile)) {
            if (input.readNBytes(magic, 0, magic.length) != magic.length) {
                throw providerFailure("Key store has an unsupported format");
            }
        } catch (IOException e) {
            throw providerFailure("Key store could not be read");
        }
        if (Arrays.equals(magic, JCEKS_MAGIC)) {
            return JCEKS;
        }
        if (Arrays.equals(magic, JKS_MAGIC)) {
            return JKS;
        }
        throw providerFailure("Key store has an unsupported format");
    }

    private void writeStore(KeyStore store) {
        atomicWrite(keyStoreFile, output -> {
            try {
                store.store(output, password);
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        });
    }

    private void atomicWrite(Path target, ContentWriter writer) {
        Path parent = target.getParent();
        Path temporary = null;
        try {
            temporary = Files.createTempFile(parent == null ? Path.of(".") : parent,
                    "sp4ks-", ".tmp");
            try (OutputStream output = Files.newOutputStream(temporary,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                writer.write(output);
            }
            applyOwnerOnly(temporary);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
            temporary = null;
        } catch (IOException e) {
            throw providerFailure("Key store could not be written");
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
            // Non-POSIX file system.
        }
    }

    private static String metaAlias(String alias) {
        return METADATA_ALIAS_PREFIX + alias;
    }

    private static void validateMatch(KeyDescriptor descriptor, KeyId keyId, KeyVersion version) {
        if (!descriptor.keyId().equals(keyId) || !descriptor.version().equals(version)) {
            throw providerFailure("Key metadata does not match the requested key");
        }
    }

    private static void verifyFingerprint(KeyDescriptor descriptor, byte[] material) {
        String expected = descriptor.fingerprint();
        if (expected == null) {
            return;
        }
        String actual = KeySupport.fingerprint(material);
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8))) {
            throw providerFailure("Key material does not match its metadata");
        }
    }

    private static StoredKey tombstone(Metadata metadata) {
        return new StoredKey(metadata.descriptor(), new byte[0], metadata.materialFormat(), true,
                Map.of());
    }

    private void requireOpen() {
        if (closed) {
            throw providerFailure("Key provider is closed");
        }
    }

    private static KeyException providerFailure(String message) {
        return new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, message);
    }

    @FunctionalInterface
    private interface ContentWriter {
        void write(OutputStream output) throws IOException;
    }
}
