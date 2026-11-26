package cn.tolim.spissatus4j.key.manager;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.audit.AuditEvent;
import cn.tolim.spissatus4j.contract.audit.AuditEventType;
import cn.tolim.spissatus4j.contract.audit.AuditOutcome;
import cn.tolim.spissatus4j.contract.audit.AuditSeverity;
import cn.tolim.spissatus4j.contract.audit.AuditTrail;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.exception.PolicyException;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyGenerationRequest;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyImportRequest;
import cn.tolim.spissatus4j.contract.key.KeyManager;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.key.KeyWrapper;
import cn.tolim.spissatus4j.contract.key.RotationPolicy;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import cn.tolim.spissatus4j.contract.spi.StoredKey;
import cn.tolim.spissatus4j.key.internal.KeyImportCodec;
import cn.tolim.spissatus4j.key.internal.KeyImportCodec.ImportedMaterial;
import cn.tolim.spissatus4j.key.internal.KeyMaterialCodec;
import cn.tolim.spissatus4j.key.internal.KeyMaterialCodec.KeyPairParts;
import cn.tolim.spissatus4j.key.internal.KeySupport;
import cn.tolim.spissatus4j.key.wrap.JcaKeyWrapper;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Default key lifecycle implementation.
 *
 * <p>Lifecycle operations are policy-checked and lifecycle changes are
 * audited. Data-use material accessors ({@link #peekForUse},
 * {@link #resolveForUse}, {@link #secretKey}, {@link #privateKey} and
 * {@link #publicKey}) deliberately do not evaluate the policy engine: the
 * facade performs the single policy decision on the read-only descriptor
 * returned by {@link #peekForUse} before resolving or reading material. Key
 * material is read from the configured {@link KeyProvider}; this manager never
 * re-encrypts provider records and never exports private material.</p>
 */
public final class DefaultKeyManager implements KeyManager {

    private static final String CROSS_TENANT_ROLE = "crypto-cross-tenant";
    private static final java.util.Set<String> DEFAULT_CROSS_TENANT_ROLES =
            java.util.Set.of(CROSS_TENANT_ROLE, "crypto-admin");
    private final java.util.Set<String> crossTenantRoles;
    private static final String ADMIN_ROLE = "crypto-admin";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KeyProvider provider;
    private final List<KeyWrapper> wrappers;
    private final PolicyEngine policyEngine;
    private final AuditTrail auditTrail;
    private final Clock clock;
    private final int defaultRetainVersions;
    private final Object lock = new Object();

    /**
     * Serializes the peek/resolve/rotate/usage-count critical section so a
     * concurrent lazy rotation cannot make another resolve fail with
     * {@code KEY_NOT_ACTIVE}.
     */
    private final Object useLock = new Object();

    private volatile boolean closed;

    public DefaultKeyManager(KeyProvider provider, List<KeyWrapper> keyWrappers,
                             PolicyEngine policyEngine, AuditTrail auditTrail, Clock clock) {
        this(provider, keyWrappers, policyEngine, auditTrail, clock,
                RotationPolicy.defaults().retainVersions());
    }

    public DefaultKeyManager(KeyProvider provider, List<KeyWrapper> keyWrappers,
                             PolicyEngine policyEngine, AuditTrail auditTrail, Clock clock,
                             int defaultRetainVersions) {
        this(provider, keyWrappers, policyEngine, auditTrail, clock, defaultRetainVersions,
                DEFAULT_CROSS_TENANT_ROLES);
    }

    public DefaultKeyManager(KeyProvider provider, List<KeyWrapper> keyWrappers,
                             PolicyEngine policyEngine, AuditTrail auditTrail, Clock clock,
                             int defaultRetainVersions, java.util.Set<String> crossTenantRoles) {
        if (provider == null || policyEngine == null || auditTrail == null || clock == null) {
            throw new cn.tolim.spissatus4j.contract.exception.ConfigurationException(
                    ErrorCode.MISSING_DEPENDENCY,
                    "Key provider, policy engine, audit trail and clock are required");
        }
        this.provider = provider;
        this.policyEngine = policyEngine;
        this.auditTrail = auditTrail;
        this.clock = clock;
        if (defaultRetainVersions < 1 || defaultRetainVersions > 1000) {
            throw new cn.tolim.spissatus4j.contract.exception.ConfigurationException(
                    ErrorCode.CONFIGURATION_INVALID,
                    "Retained key versions must be between 1 and 1000");
        }
        this.defaultRetainVersions = defaultRetainVersions;
        this.crossTenantRoles = java.util.Set.copyOf(
                java.util.Objects.requireNonNull(crossTenantRoles, "crossTenantRoles"));
        List<KeyWrapper> combined = new ArrayList<>();
        if (keyWrappers != null) {
            combined.addAll(keyWrappers);
        }
        combined.addAll(JcaKeyWrapper.defaults());
        this.wrappers = List.copyOf(combined);
    }

    /** Provider identifier used by this manager. */
    public String providerId() {
        return provider.providerId();
    }

    @Override
    public KeyDescriptor generate(KeyGenerationRequest request, CallerContext caller) {
        requireOpen();
        Objects.requireNonNull(request, "request");
        requireCaller(caller);
        KeyId keyId = request.keyId() == null ? KeySupport.randomKeyId() : request.keyId();
        KeySupport.validateTypeAlgorithm(request.type(), request.algorithm());
        enforcePolicy(Operation.GENERATE_KEY, caller, request.algorithm(), keyId, null, null,
                targetTenantAttributes(request.attributes(), request.tenantId()));
        enforceCreateTenant(request.tenantId(), caller, Operation.GENERATE_KEY);

        synchronized (lock) {
            if (loadStored(keyId, KeyVersion.first()).isPresent()) {
                throw new KeyException(ErrorCode.KEY_ALREADY_EXISTS,
                        "A key with this identifier already exists");
            }
            GeneratedMaterial generated = generateMaterial(request.type(), request.algorithm(),
                    request.keyBits());
            try {
                Instant now = clock.instant();
                KeyDescriptor descriptor = KeyDescriptor.builder()
                        .keyId(keyId)
                        .version(KeyVersion.first())
                        .type(request.type())
                        .algorithm(request.algorithm())
                        .keyBits(generated.keyBits())
                        .state(KeyState.ACTIVE)
                        .usages(KeySupport.effectiveUsages(request.type(), request.usages()))
                        .tenantId(request.tenantId())
                        .createdAt(now)
                        .activatedAt(now)
                        .rotationPolicy(effectiveRotationPolicy(request.rotationPolicy()))
                        .exportable(request.exportable())
                        .usageCount(0)
                        .attributes(request.attributes())
                        .fingerprint(KeySupport.fingerprint(generated.material()))
                        .build();
                saveStored(new StoredKey(descriptor, generated.material(),
                        generated.materialFormat(), false, Map.of()));
                audit(AuditEventType.KEY_GENERATED, AuditSeverity.INFO, AuditOutcome.SUCCESS,
                        caller, request.algorithm(), keyId, KeyVersion.first(),
                        Operation.GENERATE_KEY, "Key generated",
                        Map.of("type", request.type().name(), "state", KeyState.ACTIVE.name()));
                return descriptor;
            } finally {
                Arrays.fill(generated.material(), (byte) 0);
            }
        }
    }

    @Override
    public KeyDescriptor importKey(KeyImportRequest request, CallerContext caller) {
        requireOpen();
        Objects.requireNonNull(request, "request");
        requireCaller(caller);
        KeySupport.validateTypeAlgorithm(request.type(), request.algorithm());
        Map<String, String> importAttributes = new LinkedHashMap<>();
        importAttributes.put("format", request.format().name());
        importAttributes.put("targetTenant", request.tenantId());
        enforcePolicy(Operation.IMPORT_KEY, caller, request.algorithm(), request.keyId(), null, null,
                importAttributes);
        enforceCreateTenant(request.tenantId(), caller, Operation.IMPORT_KEY);
        ImportedMaterial imported = KeyImportCodec.decode(request);

        synchronized (lock) {
            if (loadStored(request.keyId(), KeyVersion.first()).isPresent()) {
                throw new KeyException(ErrorCode.KEY_ALREADY_EXISTS,
                        "A key with this identifier already exists");
            }
            byte[] material = imported.material();
            try {
                Instant now = clock.instant();
                KeyDescriptor descriptor = KeyDescriptor.builder()
                        .keyId(request.keyId())
                        .version(KeyVersion.first())
                        .type(request.type())
                        .algorithm(request.algorithm())
                        .keyBits(imported.keyBits())
                        .state(KeyState.PRE_ACTIVATION)
                        .usages(request.usages())
                        .tenantId(request.tenantId())
                        .createdAt(now)
                        .rotationPolicy(effectiveRotationPolicy(null))
                        .exportable(request.exportable())
                        .usageCount(0)
                        .attributes(request.attributes())
                        .fingerprint(KeySupport.fingerprint(material))
                        .build();
                saveStored(new StoredKey(descriptor, material, imported.materialFormat(), false,
                        Map.of()));
                audit(AuditEventType.KEY_IMPORTED, AuditSeverity.INFO, AuditOutcome.SUCCESS,
                        caller, request.algorithm(), request.keyId(), KeyVersion.first(),
                        Operation.IMPORT_KEY, "Key imported",
                        Map.of("format", request.format().name(),
                                "state", KeyState.PRE_ACTIVATION.name()));
                return descriptor;
            } finally {
                Arrays.fill(material, (byte) 0);
            }
        }
    }

    @Override
    public KeyDescriptor activate(KeyId keyId, KeyVersion version, CallerContext caller) {
        return lifecycle(keyId, version, caller, Operation.ACTIVATE_KEY, KeyState.ACTIVE,
                AuditEventType.KEY_ACTIVATED, AuditSeverity.INFO, "Key activated", null);
    }

    @Override
    public KeyDescriptor rotate(KeyId keyId, CallerContext caller) {
        requireOpen();
        requireCaller(caller);
        Objects.requireNonNull(keyId, "keyId");
        synchronized (useLock) {
            synchronized (lock) {
                List<StoredKey> versions = listForKey(keyId);
                if (versions.isEmpty()) {
                    throw new KeyException(ErrorCode.KEY_NOT_FOUND, "Key was not found");
                }
                StoredKey active = versions.stream()
                        .filter(stored -> stored.descriptor().state() == KeyState.ACTIVE)
                        .max(Comparator.comparingLong(
                                stored -> stored.descriptor().version().value()))
                        .orElseThrow(() -> new KeyException(ErrorCode.KEY_NOT_ACTIVE,
                                "No active key version"));
                enforcePolicy(Operation.ROTATE_KEY, caller, active.descriptor().algorithm(),
                        keyId, active.descriptor().version(), active.descriptor(), Map.of());
                checkTenant(active.descriptor(), caller, Operation.ROTATE_KEY);
                return rotateLocked(active, caller);
            }
        }
    }

    @Override
    public KeyDescriptor deactivate(KeyId keyId, KeyVersion version, CallerContext caller) {
        return lifecycle(keyId, version, caller, Operation.DEACTIVATE_KEY, KeyState.DEACTIVATED,
                AuditEventType.KEY_DEACTIVATED, AuditSeverity.INFO, "Key deactivated", null);
    }

    @Override
    public KeyDescriptor revoke(KeyId keyId, KeyVersion version, CallerContext caller,
                                String reason) {
        return lifecycle(keyId, version, caller, Operation.REVOKE_KEY, KeyState.REVOKED,
                AuditEventType.KEY_REVOKED, AuditSeverity.WARN, "Key revoked", reason);
    }

    @Override
    public KeyDescriptor compromise(KeyId keyId, KeyVersion version, CallerContext caller,
                                    String reason) {
        return lifecycle(keyId, version, caller, Operation.COMPROMISE_KEY, KeyState.COMPROMISED,
                AuditEventType.KEY_COMPROMISED, AuditSeverity.CRITICAL, "Key compromised", reason);
    }

    @Override
    public KeyDescriptor destroy(KeyId keyId, KeyVersion version, CallerContext caller) {
        requireOpen();
        requireCaller(caller);
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(version, "version");
        synchronized (lock) {
            StoredKey stored = requireStored(keyId, version);
            KeyDescriptor descriptor = stored.descriptor();
            enforcePolicy(Operation.DESTROY_KEY, caller, descriptor.algorithm(), keyId, version,
                    descriptor, Map.of());
            checkTenant(descriptor, caller, Operation.DESTROY_KEY);
            KeyState target = descriptor.state() == KeyState.COMPROMISED
                    ? KeyState.DESTROYED_COMPROMISED : KeyState.DESTROYED;
            if (!KeySupport.canTransition(descriptor.state(), target)) {
                audit(AuditEventType.KEY_DESTROYED, AuditSeverity.ERROR, AuditOutcome.FAILURE,
                        caller, descriptor.algorithm(), keyId, version, Operation.DESTROY_KEY,
                        "Key state transition rejected",
                        Map.of("state", descriptor.state().name()));
                throw new KeyException(ErrorCode.ILLEGAL_KEY_TRANSITION,
                        "Illegal key state transition");
            }
            byte[] material = stored.material();
            Arrays.fill(material, (byte) 0);
            KeyDescriptor updated = descriptor.withState(target, descriptor.activatedAt());
            saveStored(new StoredKey(updated, new byte[0], stored.materialFormat(),
                    stored.encrypted(), stored.attributes()));
            audit(AuditEventType.KEY_DESTROYED, AuditSeverity.INFO, AuditOutcome.SUCCESS,
                    caller, descriptor.algorithm(), keyId, version, Operation.DESTROY_KEY,
                    "Key destroyed", Map.of("state", target.name()));
            return updated;
        }
    }

    @Override
    public Optional<KeyDescriptor> describe(KeyId keyId, KeyVersion version,
                                            CallerContext caller) {
        requireOpen();
        requireCaller(caller);
        Objects.requireNonNull(keyId, "keyId");
        Optional<KeyDescriptor> descriptor;
        if (version != null) {
            descriptor = loadStored(keyId, version).map(StoredKey::descriptor);
        } else {
            descriptor = listForKey(keyId).stream()
                    .max(Comparator.comparingLong(stored -> stored.descriptor().version().value()))
                    .map(StoredKey::descriptor);
        }
        enforcePolicy(Operation.READ_KEY, caller,
                descriptor.map(KeyDescriptor::algorithm).orElse(null), keyId, version,
                descriptor.orElse(null), Map.of());
        if (descriptor.isPresent()) {
            checkTenant(descriptor.get(), caller, Operation.READ_KEY);
        }
        return descriptor;
    }

    @Override
    public List<KeyDescriptor> list(String tenantId, CallerContext caller) {
        requireOpen();
        requireCaller(caller);
        String target = tenantId == null || tenantId.isBlank() ? caller.tenantId()
                : tenantId.trim();
        if (!target.equals(caller.tenantId()) && !hasCrossTenantAccess(caller)) {
            audit(AuditEventType.TENANT_VIOLATION, AuditSeverity.ERROR, AuditOutcome.DENIED,
                    caller, null, null, null, Operation.READ_KEY,
                    "Cross-tenant key listing denied", Map.of());
            throw new PolicyException(ErrorCode.TENANT_VIOLATION,
                    "Cross-tenant key access denied");
        }
        Map<String, String> listAttributes = new LinkedHashMap<>();
        listAttributes.put("tenantId", target);
        listAttributes.put("targetTenant", target);
        enforcePolicy(Operation.READ_KEY, caller, null, null, null, null, listAttributes);
        List<StoredKey> stored;
        try {
            stored = provider.list(target);
        } catch (KeyException e) {
            throw e;
        } catch (RuntimeException e) {
            throw providerFailure();
        }
        return stored.stream()
                .filter(key -> target.equals(key.descriptor().tenantId()))
                .map(StoredKey::descriptor)
                .sorted(Comparator.comparing((KeyDescriptor key) -> key.keyId().value())
                        .thenComparingLong(key -> key.version().value()))
                .toList();
    }

    @Override
    public List<KeyDescriptor> versions(KeyId keyId, CallerContext caller) {
        requireOpen();
        requireCaller(caller);
        Objects.requireNonNull(keyId, "keyId");
        List<StoredKey> stored = listForKey(keyId);
        KeyDescriptor latest = stored.stream()
                .max(Comparator.comparingLong(key -> key.descriptor().version().value()))
                .map(StoredKey::descriptor)
                .orElse(null);
        enforcePolicy(Operation.READ_KEY, caller,
                latest == null ? null : latest.algorithm(), keyId, null, latest, Map.of());
        List<KeyDescriptor> result = new ArrayList<>();
        for (StoredKey key : stored) {
            checkTenant(key.descriptor(), caller, Operation.READ_KEY);
            result.add(key.descriptor());
        }
        return List.copyOf(result);
    }

    @Override
    public byte[] exportPublicKey(KeyId keyId, KeyVersion version, CallerContext caller) {
        requireOpen();
        requireCaller(caller);
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(version, "version");
        StoredKey stored = requireStored(keyId, version);
        KeyDescriptor descriptor = stored.descriptor();
        enforcePolicy(Operation.EXPORT_PUBLIC_KEY, caller, descriptor.algorithm(), keyId, version,
                descriptor, Map.of());
        checkTenant(descriptor, caller, Operation.EXPORT_PUBLIC_KEY);
        byte[] encoded = null;
        if (descriptor.state().terminal()) {
            encoded = null;
        } else if (!KeySupport.isAsymmetric(descriptor.type())) {
            encoded = null;
        } else {
            try {
                PublicKey publicKey = publicMaterial(descriptor);
                encoded = publicKey.getEncoded();
            } catch (RuntimeException e) {
                encoded = null;
            }
        }
        if (encoded == null) {
            boolean destroyed = descriptor.state().terminal();
            audit(AuditEventType.KEY_EXPORT_DENIED, AuditSeverity.WARN, AuditOutcome.DENIED,
                    caller, descriptor.algorithm(), keyId, version,
                    Operation.EXPORT_PUBLIC_KEY, "Public key export denied", Map.of());
            if (destroyed) {
                throw new KeyException(ErrorCode.KEY_DESTROYED,
                        "Key material has been destroyed");
            }
            throw new KeyException(ErrorCode.KEY_EXPORT_DENIED,
                    "Public key material is not available");
        }
        audit(AuditEventType.KEY_EXPORTED, AuditSeverity.INFO, AuditOutcome.SUCCESS, caller,
                descriptor.algorithm(), keyId, version, Operation.EXPORT_PUBLIC_KEY,
                "Public key exported", Map.of());
        return encoded;
    }

    @Override
    public byte[] wrapKey(KeyId kekId, KeyVersion kekVersion, AlgorithmId wrapAlgorithm,
                          byte[] dek, CallerContext caller) {
        requireOpen();
        requireCaller(caller);
        Objects.requireNonNull(kekId, "kekId");
        Objects.requireNonNull(wrapAlgorithm, "wrapAlgorithm");
        Objects.requireNonNull(dek, "dek");
        Long requestedVersion = kekVersion == null ? null : kekVersion.value();
        KeyDescriptor peeked = peekForUse(kekId, requestedVersion, KeyUsage.WRAP, caller);
        enforcePolicy(Operation.WRAP, caller, wrapAlgorithm, kekId, peeked.version(), peeked,
                Map.of());
        KeyDescriptor descriptor = resolveForUse(kekId, requestedVersion, KeyUsage.WRAP, caller);
        KeyWrapper wrapper = findWrapper(wrapAlgorithm);
        byte[] dekCopy = dek.clone();
        try {
            byte[] wrapped;
            if (KeySupport.usesSecretKeyMaterial(descriptor.type())) {
                wrapped = wrapper.wrap(secretMaterial(descriptor), dekCopy);
            } else {
                wrapped = wrapper.wrap(publicMaterial(descriptor), dekCopy);
            }
            audit(AuditEventType.WRAP, AuditSeverity.INFO, AuditOutcome.SUCCESS, caller,
                    wrapAlgorithm, kekId, descriptor.version(), Operation.WRAP,
                    "Data encryption key wrapped", Map.of());
            return wrapped;
        } catch (KeyException | CryptoException e) {
            audit(AuditEventType.WRAP, AuditSeverity.ERROR, AuditOutcome.FAILURE, caller,
                    wrapAlgorithm, kekId, descriptor.version(), Operation.WRAP,
                    "Key wrapping failed", Map.of());
            throw e;
        } catch (RuntimeException e) {
            audit(AuditEventType.WRAP, AuditSeverity.ERROR, AuditOutcome.FAILURE, caller,
                    wrapAlgorithm, kekId, descriptor.version(), Operation.WRAP,
                    "Key wrapping failed", Map.of());
            throw new CryptoException(ErrorCode.KEY_WRAP_FAILED, "Key wrapping failed");
        } finally {
            Arrays.fill(dekCopy, (byte) 0);
        }
    }

    @Override
    public byte[] unwrapKey(KeyId kekId, KeyVersion kekVersion, AlgorithmId wrapAlgorithm,
                            byte[] wrappedDek, CallerContext caller) {
        requireOpen();
        requireCaller(caller);
        Objects.requireNonNull(kekId, "kekId");
        Objects.requireNonNull(wrapAlgorithm, "wrapAlgorithm");
        Objects.requireNonNull(wrappedDek, "wrappedDek");
        Long requestedVersion = kekVersion == null ? null : kekVersion.value();
        KeyDescriptor peeked = peekForUse(kekId, requestedVersion, KeyUsage.UNWRAP, caller);
        enforcePolicy(Operation.UNWRAP, caller, wrapAlgorithm, kekId, peeked.version(), peeked,
                Map.of());
        KeyDescriptor descriptor = resolveForUse(kekId, requestedVersion, KeyUsage.UNWRAP,
                caller);
        KeyWrapper wrapper = findWrapper(wrapAlgorithm);
        byte[] wrappedCopy = wrappedDek.clone();
        try {
            byte[] unwrapped;
            if (KeySupport.usesSecretKeyMaterial(descriptor.type())) {
                unwrapped = wrapper.unwrap(secretMaterial(descriptor), wrappedCopy);
            } else {
                unwrapped = wrapper.unwrap(privateMaterial(descriptor), wrappedCopy);
            }
            audit(AuditEventType.UNWRAP, AuditSeverity.INFO, AuditOutcome.SUCCESS, caller,
                    wrapAlgorithm, kekId, descriptor.version(), Operation.UNWRAP,
                    "Data encryption key unwrapped", Map.of());
            return unwrapped;
        } catch (KeyException | CryptoException e) {
            audit(AuditEventType.UNWRAP, AuditSeverity.ERROR, AuditOutcome.FAILURE, caller,
                    wrapAlgorithm, kekId, descriptor.version(), Operation.UNWRAP,
                    "Key unwrapping failed", Map.of());
            throw e;
        } catch (RuntimeException e) {
            audit(AuditEventType.UNWRAP, AuditSeverity.ERROR, AuditOutcome.FAILURE, caller,
                    wrapAlgorithm, kekId, descriptor.version(), Operation.UNWRAP,
                    "Key unwrapping failed", Map.of());
            throw new CryptoException(ErrorCode.KEY_WRAP_FAILED, "Key unwrapping failed");
        } finally {
            Arrays.fill(wrappedCopy, (byte) 0);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>This implementation is the stateful half of a two-step authorization
     * performed by the facade: {@link #peekForUse} first selects the read-only
     * descriptor, the facade evaluates the policy exactly once, and only then
     * does this method perform lazy rotation and usage counting. No policy
     * engine call is made here for data-use operations; state, tenant and
     * usage checks are still enforced. Key lifecycle methods retain their own
     * policy checks.</p>
     */
    @Override
    public KeyDescriptor resolveForUse(KeyId keyId, Long requestedVersion, KeyUsage usage,
                                       CallerContext caller) {
        synchronized (useLock) {
            KeyVersion version = toKeyVersion(requestedVersion);
            KeyDescriptor descriptor = selectForUse(keyId, version, usage, caller, false);
            if (KeySupport.isProtecting(usage)) {
                if (requestedVersion == null) {
                    descriptor = maybeRotate(descriptor, caller);
                }
                descriptor = incrementUsage(descriptor);
            }
            return descriptor;
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Read-only: performs state, tenant and usage checks but never calls
     * the policy engine, rotates a key or increments a usage counter.</p>
     */
    @Override
    public KeyDescriptor peekForUse(KeyId keyId, Long requestedVersion, KeyUsage usage,
                                    CallerContext caller) {
        synchronized (useLock) {
            return selectForUse(keyId, toKeyVersion(requestedVersion), usage, caller, false);
        }
    }

    @Override
    public SecretKey secretKey(KeyId keyId, KeyVersion version, KeyUsage usage,
                               CallerContext caller) {
        KeyDescriptor descriptor = selectForUse(keyId, version, usage, caller, false);
        return secretMaterial(descriptor);
    }

    @Override
    public PrivateKey privateKey(KeyId keyId, KeyVersion version, KeyUsage usage,
                                 CallerContext caller) {
        KeyDescriptor descriptor = selectForUse(keyId, version, usage, caller, false);
        return privateMaterial(descriptor);
    }

    @Override
    public PublicKey publicKey(KeyId keyId, KeyVersion version, KeyUsage usage,
                               CallerContext caller) {
        KeyDescriptor descriptor = selectForUse(keyId, version, usage, caller, false);
        return publicMaterial(descriptor);
    }

    @Override
    public HealthStatus health() {
        if (closed) {
            return HealthStatus.DOWN;
        }
        HealthStatus providerHealth;
        try {
            providerHealth = provider.health();
        } catch (RuntimeException e) {
            providerHealth = HealthStatus.DOWN;
        }
        if (providerHealth == HealthStatus.DOWN) {
            return HealthStatus.DOWN;
        }
        return lightweightCryptoCheck() ? providerHealth : HealthStatus.DOWN;
    }

    @Override
    public void close() {
        synchronized (lock) {
            if (closed) {
                return;
            }
            closed = true;
            try {
                provider.close();
            } catch (RuntimeException ignored) {
                // Closing is best effort and idempotent.
            }
        }
    }

    private KeyDescriptor lifecycle(KeyId keyId, KeyVersion version, CallerContext caller,
                                    Operation operation, KeyState target,
                                    AuditEventType eventType, AuditSeverity severity,
                                    String message, String reason) {
        requireOpen();
        requireCaller(caller);
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(version, "version");
        if ((operation == Operation.REVOKE_KEY || operation == Operation.COMPROMISE_KEY)
                && (reason == null || reason.isBlank())) {
            throw new KeyException(ErrorCode.INVALID_PARAMETER, "A reason is required");
        }
        synchronized (lock) {
            StoredKey stored = requireStored(keyId, version);
            KeyDescriptor descriptor = stored.descriptor();
            enforcePolicy(operation, caller, descriptor.algorithm(), keyId, version, descriptor,
                    Map.of());
            checkTenant(descriptor, caller, operation);
            if (!KeySupport.canTransition(descriptor.state(), target)) {
                audit(eventType, AuditSeverity.ERROR, AuditOutcome.FAILURE, caller,
                        descriptor.algorithm(), keyId, version, operation,
                        "Key state transition rejected",
                        Map.of("state", descriptor.state().name()));
                throw new KeyException(ErrorCode.ILLEGAL_KEY_TRANSITION,
                        "Illegal key state transition");
            }
            Instant now = clock.instant();
            Instant activatedAt = descriptor.activatedAt();
            if (target == KeyState.ACTIVE && activatedAt == null) {
                activatedAt = now;
            }
            KeyDescriptor updated = descriptor.withState(target, activatedAt);
            saveStored(new StoredKey(updated, stored.material(), stored.materialFormat(),
                    stored.encrypted(), stored.attributes()));
            Map<String, String> details = new LinkedHashMap<>();
            details.put("state", target.name());
            if (reason != null) {
                details.put("reason", KeySupport.sanitizeReason(reason));
            }
            audit(eventType, severity, AuditOutcome.SUCCESS, caller, descriptor.algorithm(),
                    keyId, version, operation, message, details);
            return updated;
        }
    }

    private KeyDescriptor rotateLocked(StoredKey active, CallerContext caller) {
        KeyDescriptor current = active.descriptor();
        GeneratedMaterial generated = generateMaterial(current.type(), current.algorithm(),
                current.keyBits());
        try {
            long highest = listForKey(current.keyId()).stream()
                    .mapToLong(stored -> stored.descriptor().version().value())
                    .max()
                    .orElse(current.version().value());
            KeyVersion next = KeyVersion.of(Math.addExact(highest, 1L));
            Instant now = clock.instant();
            KeyDescriptor rotated = KeyDescriptor.builder()
                    .keyId(current.keyId())
                    .version(next)
                    .type(current.type())
                    .algorithm(current.algorithm())
                    .keyBits(generated.keyBits())
                    .state(KeyState.ACTIVE)
                    .usages(current.usages())
                    .tenantId(current.tenantId())
                    .createdAt(now)
                    .activatedAt(now)
                    .rotationPolicy(current.rotationPolicy())
                    .exportable(current.exportable())
                    .usageCount(0)
                    .attributes(current.attributes())
                    .fingerprint(KeySupport.fingerprint(generated.material()))
                    .build();
            // Fail closed: retire the old ACTIVE version before publishing the
            // new one. A crash between writes can leave no ACTIVE version, but
            // never two simultaneously usable versions.
            if (current.state() == KeyState.ACTIVE) {
                KeyDescriptor deactivated = current.withState(KeyState.DEACTIVATED,
                        current.activatedAt());
                saveStored(new StoredKey(deactivated, active.material(), active.materialFormat(),
                        active.encrypted(), active.attributes()));
            }
            saveStored(new StoredKey(rotated, generated.material(), generated.materialFormat(),
                    active.encrypted(), active.attributes()));
            audit(AuditEventType.KEY_ROTATED, AuditSeverity.INFO, AuditOutcome.SUCCESS, caller,
                    rotated.algorithm(), current.keyId(), next, Operation.ROTATE_KEY,
                    "Key rotated", Map.of("previousVersion", current.version().toString()));
            destroyBeyondRetention(current.keyId(), current.rotationPolicy(), caller);
            return rotated;
        } finally {
            Arrays.fill(generated.material(), (byte) 0);
        }
    }

    private void destroyBeyondRetention(KeyId keyId, RotationPolicy policy,
                                        CallerContext caller) {
        int retain = policy == null ? defaultRetainVersions : policy.retainVersions();
        List<StoredKey> versions = listForKey(keyId);
        int destroyCount = versions.size() - retain;
        for (int i = 0; i < destroyCount; i++) {
            StoredKey stored = versions.get(i);
            KeyDescriptor descriptor = stored.descriptor();
            if (descriptor.state().terminal()) {
                continue;
            }
            KeyState target = descriptor.state() == KeyState.COMPROMISED
                    ? KeyState.DESTROYED_COMPROMISED : KeyState.DESTROYED;
            if (!KeySupport.canTransition(descriptor.state(), target)) {
                continue;
            }
            KeyDescriptor tombstone = descriptor.withState(target, descriptor.activatedAt());
            saveStored(new StoredKey(tombstone, new byte[0], stored.materialFormat(),
                    stored.encrypted(), stored.attributes()));
            audit(AuditEventType.KEY_DESTROYED, AuditSeverity.INFO, AuditOutcome.SUCCESS,
                    caller, descriptor.algorithm(), keyId, descriptor.version(),
                    Operation.DESTROY_KEY, "Key version destroyed by retention",
                    Map.of("state", target.name()));
        }
    }

    private KeyDescriptor maybeRotate(KeyDescriptor descriptor, CallerContext caller) {
        RotationPolicy policy = descriptor.rotationPolicy();
        if (policy == null || !rotationTriggered(descriptor)) {
            return descriptor;
        }
        // Lazy rotation is part of an already-authorized data operation; it must
        // not consume a second policy decision/rate-limit token. Explicit
        // rotate(...) continues to enforce the ROTATE_KEY policy.
        synchronized (lock) {
            Optional<StoredKey> loaded = loadStored(descriptor.keyId(), descriptor.version());
            if (loaded.isEmpty()) {
                return descriptor;
            }
            StoredKey current = loaded.get();
            KeyDescriptor currentDescriptor = current.descriptor();
            if (currentDescriptor.state() != KeyState.ACTIVE) {
                throw new KeyException(ErrorCode.KEY_NOT_ACTIVE, "Key is not active");
            }
            RotationPolicy currentPolicy = currentDescriptor.rotationPolicy();
            if (currentPolicy == null || !rotationTriggered(currentDescriptor)) {
                return currentDescriptor;
            }
            return rotateLocked(current, caller);
        }
    }

    private boolean rotationTriggered(KeyDescriptor descriptor) {
        RotationPolicy policy = descriptor.rotationPolicy();
        if (policy == null) {
            return false;
        }
        Instant now = clock.instant();
        return policy.ageTriggered(descriptor.createdAt(), now)
                || policy.operationsTriggered(descriptor.usageCount());
    }

    private KeyDescriptor incrementUsage(KeyDescriptor descriptor) {
        synchronized (lock) {
            try {
                Optional<StoredKey> loaded = provider.load(descriptor.keyId(),
                        descriptor.version());
                if (loaded.isEmpty()) {
                    return descriptor;
                }
                StoredKey current = loaded.get();
                KeyDescriptor currentDescriptor = current.descriptor();
                if (currentDescriptor.state() != KeyState.ACTIVE) {
                    return descriptor;
                }
                KeyDescriptor updated = currentDescriptor.withUsageCount(
                        Math.addExact(currentDescriptor.usageCount(), 1L));
                saveStored(new StoredKey(updated, current.material(),
                        current.materialFormat(), current.encrypted(), current.attributes()));
                return updated;
            } catch (RuntimeException ignored) {
                // Usage counting is best effort and never fails an operation.
                return descriptor;
            }
        }
    }

    private KeyDescriptor selectForUse(KeyId keyId, KeyVersion requestedVersion, KeyUsage usage,
                                       CallerContext caller, boolean checkPolicy) {
        requireOpen();
        requireCaller(caller);
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(usage, "usage");
        List<StoredKey> versions = listForKey(keyId);
        if (versions.isEmpty()) {
            throw new KeyException(ErrorCode.KEY_NOT_FOUND, "Key was not found");
        }
        StoredKey selected;
        if (requestedVersion != null) {
            selected = versions.stream()
                    .filter(stored -> stored.descriptor().version().equals(requestedVersion))
                    .findFirst()
                    .orElseThrow(() -> new KeyException(ErrorCode.KEY_VERSION_NOT_FOUND,
                            "Key version was not found"));
        } else {
            selected = versions.stream()
                    .filter(stored -> stored.descriptor().state() == KeyState.ACTIVE)
                    .max(Comparator.comparingLong(
                            stored -> stored.descriptor().version().value()))
                    .orElseThrow(() -> new KeyException(ErrorCode.KEY_NOT_ACTIVE,
                            "No active key version"));
        }
        KeyDescriptor descriptor = selected.descriptor();
        Operation operation = operationForUsage(usage);
        checkTenant(descriptor, caller, operation);
        if (checkPolicy) {
            enforcePolicy(operation, caller, descriptor.algorithm(), keyId,
                    descriptor.version(), descriptor, Map.of());
        }
        enforceUsable(descriptor, usage, clock.instant());
        return descriptor;
    }

    private void enforceUsable(KeyDescriptor descriptor, KeyUsage usage, Instant now) {
        KeyState state = descriptor.state();
        if (state.terminal()) {
            throw new KeyException(ErrorCode.KEY_DESTROYED, "Key material has been destroyed");
        }
        boolean protecting = KeySupport.isProtecting(usage);
        if (protecting || usage == KeyUsage.DERIVE) {
            if (state != KeyState.ACTIVE) {
                throw new KeyException(ErrorCode.KEY_NOT_ACTIVE, "Key is not active");
            }
        } else if (!state.canProcessHistoricalData()) {
            throw new KeyException(ErrorCode.KEY_NOT_ACTIVE,
                    "Key is not usable for historical data");
        }
        if (protecting && descriptor.expired(now)) {
            throw new KeyException(ErrorCode.KEY_NOT_ACTIVE, "Key is expired");
        }
        if (!descriptor.supportsUsage(usage)) {
            throw new KeyException(ErrorCode.KEY_USAGE_VIOLATION,
                    "Key does not permit the requested usage");
        }
    }

    private SecretKey secretMaterial(KeyDescriptor descriptor) {
        StoredKey stored = requireStored(descriptor.keyId(), descriptor.version());
        if (stored.descriptor().state().terminal()) {
            throw new KeyException(ErrorCode.KEY_DESTROYED, "Key material has been destroyed");
        }
        if (!KeyMaterialCodec.RAW.equals(stored.materialFormat())) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                    "Key version has no symmetric key material");
        }
        byte[] material = stored.material();
        if (material.length == 0) {
            throw new KeyException(ErrorCode.KEY_DESTROYED, "Key material has been destroyed");
        }
        try {
            return new SecretKeySpec(material,
                    KeySupport.jcaKeyAlgorithm(descriptor.algorithm(), descriptor.type()));
        } catch (IllegalArgumentException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                    "Key material could not be decoded");
        } finally {
            Arrays.fill(material, (byte) 0);
        }
    }

    private PrivateKey privateMaterial(KeyDescriptor descriptor) {
        StoredKey stored = requireStored(descriptor.keyId(), descriptor.version());
        if (stored.descriptor().state().terminal()) {
            throw new KeyException(ErrorCode.KEY_DESTROYED, "Key material has been destroyed");
        }
        String format = stored.materialFormat();
        byte[] privateDer = null;
        byte[] publicDer = null;
        if (KeyMaterialCodec.KEYPAIR.equals(format)) {
            KeyPairParts parts = KeyMaterialCodec.decodeKeyPair(stored.material());
            privateDer = parts.privateDer();
            publicDer = parts.publicDer();
        } else if (KeyMaterialCodec.PKCS8.equals(format)) {
            privateDer = stored.material();
        }
        if (privateDer == null) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                    "Key version has no private key material");
        }
        try {
            KeyFactory factory = KeySupport.keyFactory(descriptor.type());
            return factory.generatePrivate(new PKCS8EncodedKeySpec(privateDer));
        } catch (InvalidKeySpecException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                    "Private key material could not be decoded");
        } finally {
            Arrays.fill(privateDer, (byte) 0);
            if (publicDer != null) {
                Arrays.fill(publicDer, (byte) 0);
            }
        }
    }

    private PublicKey publicMaterial(KeyDescriptor descriptor) {
        StoredKey stored = requireStored(descriptor.keyId(), descriptor.version());
        if (stored.descriptor().state().terminal()) {
            throw new KeyException(ErrorCode.KEY_DESTROYED, "Key material has been destroyed");
        }
        String format = stored.materialFormat();
        byte[] publicDer = null;
        byte[] privateDer = null;
        if (KeyMaterialCodec.KEYPAIR.equals(format)) {
            KeyPairParts parts = KeyMaterialCodec.decodeKeyPair(stored.material());
            publicDer = parts.publicDer();
            privateDer = parts.privateDer();
        } else if (KeyMaterialCodec.X509.equals(format)) {
            publicDer = stored.material();
        }
        if (publicDer == null) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                    "Key version has no public key material");
        }
        try {
            KeyFactory factory = KeySupport.keyFactory(descriptor.type());
            return factory.generatePublic(new X509EncodedKeySpec(publicDer));
        } catch (InvalidKeySpecException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                    "Public key material could not be decoded");
        } finally {
            Arrays.fill(publicDer, (byte) 0);
            if (privateDer != null) {
                Arrays.fill(privateDer, (byte) 0);
            }
        }
    }

    private KeyWrapper findWrapper(AlgorithmId algorithm) {
        for (KeyWrapper wrapper : wrappers) {
            if (wrapper.supports(algorithm)) {
                return wrapper;
            }
        }
        throw new CryptoException(ErrorCode.ALGORITHM_UNSUPPORTED,
                "No key wrapper supports algorithm " + algorithm.id());
    }

    private GeneratedMaterial generateMaterial(KeyType type, AlgorithmId algorithm,
                                               int requestedBits) {
        try {
            if (KeySupport.isAsymmetric(type)) {
                return generatePair(type, algorithm, requestedBits);
            }
            return generateSecret(type, algorithm, requestedBits);
        } catch (KeyException e) {
            throw e;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new KeyException(ErrorCode.ALGORITHM_UNSUPPORTED,
                    "Key generation algorithm is not available");
        } catch (GeneralSecurityException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, "Key generation failed");
        } catch (RuntimeException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, "Key generation failed");
        }
    }

    private GeneratedMaterial generateSecret(KeyType type, AlgorithmId algorithm,
                                             int requestedBits) throws GeneralSecurityException {
        if (algorithm.equals(AlgorithmId.CHACHA20_POLY1305)) {
            int bits = requestedBits == 0 ? 256 : requestedBits;
            if (bits != 256) {
                throw new KeyException(ErrorCode.MIN_KEY_BITS_VIOLATION,
                        "ChaCha20-Poly1305 keys must be 256 bits");
            }
            try {
                KeyGenerator generator = KeyGenerator.getInstance("ChaCha20");
                generator.init(256, RANDOM);
                byte[] encoded = generator.generateKey().getEncoded();
                return new GeneratedMaterial(KeyMaterialCodec.RAW, encoded, 256);
            } catch (NoSuchAlgorithmException e) {
                throw new KeyException(ErrorCode.ALGORITHM_UNSUPPORTED,
                        "ChaCha20 key generation is not available");
            }
        }
        if (KeySupport.jcaKeyAlgorithm(algorithm, type).equals("AES")
                && !algorithm.equals(AlgorithmId.CMAC_AES)) {
            int bits = requestedBits == 0 ? 256 : requestedBits;
            if (bits != 128 && bits != 192 && bits != 256) {
                throw new KeyException(ErrorCode.MIN_KEY_BITS_VIOLATION,
                        "AES keys must be 128, 192 or 256 bits");
            }
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(bits, RANDOM);
            return new GeneratedMaterial(KeyMaterialCodec.RAW,
                    generator.generateKey().getEncoded(), bits);
        }
        if (KeySupport.jcaKeyAlgorithm(algorithm, type).equals("SM4")) {
            if (requestedBits != 0 && requestedBits != 128) {
                throw new KeyException(ErrorCode.MIN_KEY_BITS_VIOLATION,
                        "SM4 keys must be 128 bits");
            }
            Provider bc = Security.getProvider("BC");
            if (bc != null) {
                KeyGenerator generator = KeyGenerator.getInstance("SM4", bc);
                generator.init(128, RANDOM);
                return new GeneratedMaterial(KeyMaterialCodec.RAW,
                        generator.generateKey().getEncoded(), 128);
            }
            return new GeneratedMaterial(KeyMaterialCodec.RAW, KeySupport.randomBytes(16), 128);
        }
        if (KeySupport.jcaKeyAlgorithm(algorithm, type).startsWith("Hmac")
                && KeySupport.jcaKeyAlgorithm(algorithm, type) != null) {
            int bits = requestedBits == 0 ? 256 : requestedBits;
            if (bits < 256) {
                throw new KeyException(ErrorCode.MIN_KEY_BITS_VIOLATION,
                        "HMAC keys must be at least 256 bits");
            }
            if (bits % 8 != 0) {
                throw new KeyException(ErrorCode.INVALID_PARAMETER,
                        "HMAC key size must be a multiple of 8 bits");
            }
            KeyGenerator generator = KeyGenerator.getInstance(
                    KeySupport.jcaKeyAlgorithm(algorithm, type));
            generator.init(bits, RANDOM);
            return new GeneratedMaterial(KeyMaterialCodec.RAW,
                    generator.generateKey().getEncoded(), bits);
        }
        throw new KeyException(ErrorCode.ALGORITHM_UNSUPPORTED,
                "Key generation is not supported for this algorithm");
    }

    private GeneratedMaterial generatePair(KeyType type, AlgorithmId algorithm,
                                           int requestedBits) throws GeneralSecurityException {
        KeyPair pair;
        int keyBits;
        if (KeySupport.jcaKeyAlgorithm(algorithm, type).equals("RSA")) {
            int bits = requestedBits == 0 ? 3072 : requestedBits;
            if (bits < 2048) {
                throw new KeyException(ErrorCode.MIN_KEY_BITS_VIOLATION,
                        "RSA keys must be at least 2048 bits");
            }
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits, RANDOM);
            pair = generator.generateKeyPair();
            keyBits = bits;
        } else if (algorithm.equals(AlgorithmId.ED25519)) {
            checkFixedBits(requestedBits, 256);
            pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            keyBits = 256;
        } else if (algorithm.equals(AlgorithmId.ED448)) {
            checkFixedBits(requestedBits, 456);
            pair = KeyPairGenerator.getInstance("Ed448").generateKeyPair();
            keyBits = 456;
        } else if (algorithm.equals(AlgorithmId.SM2) || algorithm.equals(AlgorithmId.SM2_SIGNATURE)) {
            checkFixedBits(requestedBits, 256);
            if (Security.getProvider("BC") == null) {
                throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                        "SM2 key generation requires the Bouncy Castle provider");
            }
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
            generator.initialize(new ECGenParameterSpec("sm2p256v1"), RANDOM);
            pair = generator.generateKeyPair();
            keyBits = 256;
        } else if (algorithm.equals(AlgorithmId.ECDSA_P256)
                || algorithm.equals(AlgorithmId.ECDSA_P384) || algorithm.equals(AlgorithmId.ECIES)) {
            int expectedBits = algorithm.equals(AlgorithmId.ECDSA_P384) ? 384 : 256;
            checkFixedBits(requestedBits, expectedBits);
            String curve = expectedBits == 384 ? "secp384r1" : "secp256r1";
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve), RANDOM);
            pair = generator.generateKeyPair();
            keyBits = expectedBits;
        } else {
            throw new KeyException(ErrorCode.ALGORITHM_UNSUPPORTED,
                    "Key generation is not supported for this algorithm");
        }
        return new GeneratedMaterial(KeyMaterialCodec.KEYPAIR,
                KeyMaterialCodec.encodeKeyPair(pair.getPrivate().getEncoded(),
                        pair.getPublic().getEncoded()),
                keyBits);
    }

    private static void checkFixedBits(int requestedBits, int expectedBits) {
        if (requestedBits != 0 && requestedBits != expectedBits) {
            throw new KeyException(ErrorCode.INVALID_PARAMETER,
                    "Requested key size is not supported for this algorithm");
        }
    }

    private RotationPolicy effectiveRotationPolicy(RotationPolicy requested) {
        if (requested == null) {
            return RotationPolicy.defaults().withRetainVersions(defaultRetainVersions);
        }
        return requested;
    }

    private void enforcePolicy(Operation operation, CallerContext caller, AlgorithmId algorithm,
                               KeyId keyId, KeyVersion version, KeyDescriptor descriptor,
                               Map<String, String> attributes) {
        PolicyDecision decision;
        try {
            decision = policyEngine.evaluate(PolicyRequest.builder(operation, caller)
                    .algorithm(algorithm)
                    .keyId(keyId)
                    .keyVersion(version)
                    .key(descriptor)
                    .attributes(attributes)
                    .build());
        } catch (RuntimeException e) {
            throw new PolicyException(ErrorCode.POLICY_UNAVAILABLE,
                    "Policy evaluation is unavailable");
        }
        if (decision == null || decision.denied()) {
            audit(AuditEventType.POLICY_DENIED, AuditSeverity.WARN, AuditOutcome.DENIED, caller,
                    algorithm, keyId, version, operation, "Operation denied by policy", Map.of());
            throw new PolicyException(ErrorCode.POLICY_DENIED,
                    "Operation denied by security policy");
        }
        if (decision.warned()) {
            audit(AuditEventType.POLICY_WARNING, AuditSeverity.WARN, AuditOutcome.INFO, caller,
                    algorithm, keyId, version, operation, "Policy warning",
                    Map.of("reasonCode", decision.reasonCode()));
        }
    }

    private void checkTenant(KeyDescriptor descriptor, CallerContext caller,
                             Operation operation) {
        if (!descriptor.tenantId().equals(caller.tenantId()) && !hasCrossTenantAccess(caller)) {
            audit(AuditEventType.TENANT_VIOLATION, AuditSeverity.ERROR, AuditOutcome.DENIED,
                    caller, descriptor.algorithm(), descriptor.keyId(), descriptor.version(),
                    operation, "Cross-tenant key access denied", Map.of());
            throw new PolicyException(ErrorCode.TENANT_VIOLATION,
                    "Cross-tenant key access denied");
        }
    }

    private void enforceCreateTenant(String tenantId, CallerContext caller, Operation operation) {
        if (!tenantId.equals(caller.tenantId()) && !hasCrossTenantAccess(caller)) {
            audit(AuditEventType.TENANT_VIOLATION, AuditSeverity.ERROR, AuditOutcome.DENIED,
                    caller, null, null, null, operation, "Cross-tenant key creation denied",
                    Map.of());
            throw new PolicyException(ErrorCode.TENANT_VIOLATION,
                    "Cross-tenant key creation denied");
        }
    }

    private boolean hasCrossTenantAccess(CallerContext caller) {
        for (String role : crossTenantRoles) {
            if (caller.hasRole(role)) {
                return true;
            }
        }
        return false;
    }

    private static Map<String, String> targetTenantAttributes(Map<String, String> attributes,
                                                              String targetTenant) {
        Map<String, String> result = new LinkedHashMap<>(attributes);
        result.put("targetTenant", targetTenant);
        return result;
    }

    private static Operation operationForUsage(KeyUsage usage) {
        return switch (usage) {
            case ENCRYPT -> Operation.ENCRYPT;
            case DECRYPT -> Operation.DECRYPT;
            case SIGN -> Operation.SIGN;
            case VERIFY -> Operation.VERIFY;
            case WRAP -> Operation.WRAP;
            case UNWRAP -> Operation.UNWRAP;
            case MAC -> Operation.MAC;
            case DERIVE -> Operation.DERIVE_KEY;
        };
    }

    private StoredKey requireStored(KeyId keyId, KeyVersion version) {
        Optional<StoredKey> stored = loadStored(keyId, version);
        if (stored.isPresent()) {
            return stored.get();
        }
        if (listForKey(keyId).isEmpty()) {
            throw new KeyException(ErrorCode.KEY_NOT_FOUND, "Key was not found");
        }
        throw new KeyException(ErrorCode.KEY_VERSION_NOT_FOUND, "Key version was not found");
    }

    private Optional<StoredKey> loadStored(KeyId keyId, KeyVersion version) {
        try {
            return provider.load(keyId, version);
        } catch (KeyException e) {
            throw e;
        } catch (RuntimeException e) {
            throw providerFailure();
        }
    }

    private List<StoredKey> listForKey(KeyId keyId) {
        List<StoredKey> all;
        try {
            all = provider.list(null);
        } catch (KeyException e) {
            throw e;
        } catch (RuntimeException e) {
            throw providerFailure();
        }
        return all.stream()
                .filter(stored -> stored.descriptor().keyId().equals(keyId))
                .sorted(Comparator.comparingLong(stored -> stored.descriptor().version().value()))
                .toList();
    }

    private void saveStored(StoredKey storedKey) {
        try {
            provider.save(storedKey);
        } catch (KeyException e) {
            throw e;
        } catch (RuntimeException e) {
            throw providerFailure();
        }
    }

    private void audit(AuditEventType type, AuditSeverity severity, AuditOutcome outcome,
                       CallerContext caller, AlgorithmId algorithm, KeyId keyId,
                       KeyVersion version, Operation operation, String message,
                       Map<String, String> details) {
        AuditEvent event = AuditEvent.builder(type, severity, outcome)
                .timestamp(clock.instant())
                .caller(caller)
                .algorithm(algorithm)
                .keyId(keyId)
                .keyVersion(version)
                .operation(operation)
                .message(message)
                .details(details)
                .build();
        auditTrail.append(event);
    }

    private static boolean lightweightCryptoCheck() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(128);
            SecretKey key = generator.generateKey();
            byte[] nonce = KeySupport.randomBytes(12);
            byte[] plaintext = {0x01, 0x02, 0x03};
            Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
            encrypt.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            byte[] ciphertext = encrypt.doFinal(plaintext);
            Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
            decrypt.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            return MessageDigest.isEqual(plaintext, decrypt.doFinal(ciphertext));
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static KeyVersion toKeyVersion(Long requestedVersion) {
        if (requestedVersion == null) {
            return null;
        }
        try {
            return KeyVersion.of(requestedVersion);
        } catch (IllegalArgumentException e) {
            throw new KeyException(ErrorCode.KEY_VERSION_NOT_FOUND, "Key version was not found");
        }
    }

    private static void requireCaller(CallerContext caller) {
        Objects.requireNonNull(caller, "caller");
    }

    private void requireOpen() {
        if (closed) {
            throw providerFailure();
        }
    }

    private static KeyException providerFailure() {
        return new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, "Key provider failure");
    }

    private record GeneratedMaterial(String materialFormat, byte[] material, int keyBits) {
    }
}