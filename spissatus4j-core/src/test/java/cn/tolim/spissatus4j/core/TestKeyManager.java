package cn.tolim.spissatus4j.core;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyGenerationRequest;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyImportRequest;
import cn.tolim.spissatus4j.contract.key.KeyManager;
import cn.tolim.spissatus4j.contract.key.KeySelectionCandidate;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/** Minimal in-memory key manager for core facade tests. */
final class TestKeyManager implements KeyManager {

    static final KeyId KEY_ID = KeyId.of("test-key");
    static final KeyVersion VERSION = KeyVersion.first();
    static final String TENANT = "tenant-a";

    private final KeyDescriptor descriptor;
    private final SecretKey secretKey;

    TestKeyManager() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256);
            this.secretKey = generator.generateKey();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        Instant now = Instant.now();
        this.descriptor = KeyDescriptor.builder()
                .keyId(KEY_ID)
                .version(VERSION)
                .type(KeyType.AES)
                .algorithm(AlgorithmId.AES_GCM)
                .keyBits(256)
                .state(KeyState.ACTIVE)
                .usages(Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT))
                .tenantId(TENANT)
                .createdAt(now)
                .activatedAt(now)
                .build();
    }

    @Override
    public KeyDescriptor resolveForUse(KeyId keyId, Long requestedVersion, KeyUsage usage,
                                       CallerContext caller) {
        checkIdentity(keyId, requestedVersion);
        if (!descriptor.supportsUsage(usage)) {
            throw new KeyException(ErrorCode.KEY_USAGE_VIOLATION, "Usage not permitted");
        }
        if (!descriptor.state().canProcessHistoricalData()) {
            throw new KeyException(ErrorCode.KEY_NOT_ACTIVE, "Key is not active");
        }
        return descriptor;
    }

    @Override
    public SecretKey secretKey(KeyId keyId, KeyVersion version, KeyUsage usage, CallerContext caller) {
        checkIdentity(keyId, version == null ? null : version.value());
        return secretKey;
    }

    @Override
    public PrivateKey privateKey(KeyId keyId, KeyVersion version, KeyUsage usage, CallerContext caller) {
        throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, "No private key");
    }

    @Override
    public PublicKey publicKey(KeyId keyId, KeyVersion version, KeyUsage usage, CallerContext caller) {
        throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, "No public key");
    }

    private void checkIdentity(KeyId keyId, Long version) {
        if (!KEY_ID.equals(keyId)) {
            throw new KeyException(ErrorCode.KEY_NOT_FOUND, "Key not found");
        }
        if (version != null && version != VERSION.value()) {
            throw new KeyException(ErrorCode.KEY_VERSION_NOT_FOUND, "Key version not found");
        }
    }

    @Override
    public KeyDescriptor generate(KeyGenerationRequest request, CallerContext caller) {
        throw new UnsupportedOperationException("test manager");
    }

    @Override
    public KeyDescriptor importKey(KeyImportRequest request, CallerContext caller) {
        throw new UnsupportedOperationException("test manager");
    }

    @Override
    public KeyDescriptor activate(KeyId keyId, KeyVersion version, CallerContext caller) {
        throw new UnsupportedOperationException("test manager");
    }

    @Override
    public KeyDescriptor rotate(KeyId keyId, CallerContext caller) {
        throw new UnsupportedOperationException("test manager");
    }

    @Override
    public KeyDescriptor deactivate(KeyId keyId, KeyVersion version, CallerContext caller) {
        throw new UnsupportedOperationException("test manager");
    }

    @Override
    public KeyDescriptor revoke(KeyId keyId, KeyVersion version, CallerContext caller, String reason) {
        throw new UnsupportedOperationException("test manager");
    }

    @Override
    public KeyDescriptor compromise(KeyId keyId, KeyVersion version, CallerContext caller,
                                    String reason) {
        throw new UnsupportedOperationException("test manager");
    }

    @Override
    public KeyDescriptor destroy(KeyId keyId, KeyVersion version, CallerContext caller) {
        throw new UnsupportedOperationException("test manager");
    }

    @Override
    public Optional<KeyDescriptor> describe(KeyId keyId, KeyVersion version, CallerContext caller) {
        return KEY_ID.equals(keyId) && (version == null || version.equals(VERSION))
                ? Optional.of(descriptor) : Optional.empty();
    }

    @Override
    public List<KeyDescriptor> list(String tenantId, CallerContext caller) {
        return List.of(descriptor);
    }

    @Override
    public List<KeySelectionCandidate> candidateKeys(KeyUsage usage, CallerContext caller,
                                                     int limit) {
        if (limit < 1 || !descriptor.supportsUsage(usage)
                || !descriptor.tenantId().equals(caller.tenantId())) {
            return List.of();
        }
        return List.of(KeySelectionCandidate.from(descriptor));
    }

    @Override
    public List<KeyDescriptor> versions(KeyId keyId, CallerContext caller) {
        return List.of(descriptor);
    }

    @Override
    public byte[] exportPublicKey(KeyId keyId, KeyVersion version, CallerContext caller) {
        throw new KeyException(ErrorCode.KEY_EXPORT_DENIED, "Private/symmetric export denied");
    }

    @Override
    public byte[] wrapKey(KeyId kekId, KeyVersion kekVersion, AlgorithmId wrapAlgorithm, byte[] dek,
                          CallerContext caller) {
        throw new KeyException(ErrorCode.UNSUPPORTED_OPERATION, "Wrapping not supported");
    }

    @Override
    public byte[] unwrapKey(KeyId kekId, KeyVersion kekVersion, AlgorithmId wrapAlgorithm,
                            byte[] wrappedDek, CallerContext caller) {
        throw new KeyException(ErrorCode.UNSUPPORTED_OPERATION, "Wrapping not supported");
    }

    @Override
    public HealthStatus health() {
        return HealthStatus.UP;
    }

    @Override
    public void close() {
    }
}