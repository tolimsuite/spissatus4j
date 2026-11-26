package cn.tolim.spissatus4j.key.provider;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyState;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import cn.tolim.spissatus4j.contract.spi.StoredKey;
import cn.tolim.spissatus4j.key.internal.KeyMaterialCodec;
import cn.tolim.spissatus4j.key.internal.KeySupport;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Read-only key provider backed by environment variables.
 *
 * <p>Environment variables are named {@code <prefix><sanitized-key-id>} for
 * version 1 or {@code <prefix><sanitized-key-id>_V<n>} for later versions. The
 * sanitized form upper-cases the key id and replaces characters outside
 * {@code [A-Z0-9]} with {@code _}; if the result starts with {@code _} or a
 * digit, a {@code K} prefix is added. Values are Base64-encoded RAW secret
 * keys. The descriptor is derived best-effort: 16/24/32-byte values are
 * treated as AES keys for encryption, all other lengths as HMAC-SHA256 MAC
 * keys, and all keys are reported in the {@code default} tenant.</p>
 *
 * <p>Limitations: names are not reversible in all cases (for example
 * {@code a-b} and {@code a_b} map to the same variable), no timestamps or
 * rotation policy are available, and all entries are reported as ACTIVE.
 * Environments are immutable in the JVM, so {@link #save} and {@link #delete}
 * always fail.</p>
 */
public final class EnvironmentKeyProvider implements KeyProvider {

    public static final String PROVIDER_ID = "environment";
    public static final String DEFAULT_PREFIX = "SPISSATUS_KEY_";

    private static final Pattern VERSION_SUFFIX = Pattern.compile("^(.+?)_V(\\d+)$");
    private static final Instant EPOCH = Instant.EPOCH;

    private final String prefix;
    private final Map<String, String> environment;

    public EnvironmentKeyProvider(String prefix) {
        this(prefix, System.getenv());
    }

    EnvironmentKeyProvider(String prefix, Map<String, String> environment) {
        String candidate = prefix == null || prefix.isBlank() ? DEFAULT_PREFIX : prefix.trim();
        if (!candidate.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            throw new IllegalArgumentException("Invalid environment prefix");
        }
        this.prefix = candidate;
        this.environment = Map.copyOf(Objects.requireNonNull(environment, "environment"));
    }

    @Override
    public String providerId() {
        return PROVIDER_ID;
    }

    @Override
    public Optional<StoredKey> load(KeyId keyId, KeyVersion version) {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(version, "version");
        String base = prefix + KeySupport.environmentSuffix(keyId);
        String value = environment.get(base + "_V" + version.value());
        if (value == null && version.value() == 1) {
            value = environment.get(base);
        }
        if (value == null) {
            return Optional.empty();
        }
        return Optional.of(storedKey(keyId, version, value));
    }

    @Override
    public void save(StoredKey storedKey) {
        throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                "Environment key provider is read-only");
    }

    @Override
    public boolean delete(KeyId keyId, KeyVersion version) {
        throw new KeyException(ErrorCode.UNSUPPORTED_OPERATION,
                "Environment key provider does not support deletion");
    }

    @Override
    public List<StoredKey> list(String tenantId) {
        if (tenantId != null && !"default".equals(tenantId)) {
            return List.of();
        }
        List<StoredKey> result = new ArrayList<>();
        for (Map.Entry<String, String> entry : environment.entrySet()) {
            String name = entry.getKey();
            if (!name.startsWith(prefix)) {
                continue;
            }
            ParsedName parsed = parseName(name.substring(prefix.length()));
            if (parsed == null) {
                continue;
            }
            try {
                result.add(storedKey(parsed.keyId(), parsed.version(), entry.getValue()));
            } catch (KeyException e) {
                // A malformed individual variable must not break list(); load() reports it.
            }
        }
        result.sort(Comparator.comparing((StoredKey key) -> key.descriptor().keyId().value())
                .thenComparingLong(key -> key.descriptor().version().value()));
        return List.copyOf(result);
    }

    @Override
    public HealthStatus health() {
        return HealthStatus.UP;
    }

    @Override
    public void close() {
        // Environment variables are process-owned; nothing to close.
    }

    private StoredKey storedKey(KeyId keyId, KeyVersion version, String base64Value) {
        byte[] material;
        try {
            String candidate = base64Value.trim();
            if (candidate.isEmpty()) {
                throw new IllegalArgumentException("empty");
            }
            try {
                material = Base64.getDecoder().decode(candidate);
            } catch (IllegalArgumentException standardFailure) {
                material = Base64.getUrlDecoder().decode(candidate);
            }
        } catch (RuntimeException e) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                    "Environment key value is not valid Base64");
        }
        if (material.length == 0) {
            throw new KeyException(ErrorCode.KEY_PROVIDER_FAILURE,
                    "Environment key value is empty");
        }
        boolean aesSized = material.length == 16 || material.length == 24 || material.length == 32;
        KeyType type = aesSized ? KeyType.AES : KeyType.HMAC;
        AlgorithmId algorithm = aesSized ? AlgorithmId.AES_GCM : AlgorithmId.HMAC_SHA256;
        Set<KeyUsage> usages = aesSized
                ? Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                : Set.of(KeyUsage.MAC);
        KeyDescriptor descriptor = KeyDescriptor.builder()
                .keyId(keyId)
                .version(version)
                .type(type)
                .algorithm(algorithm)
                .keyBits(material.length * 8)
                .state(KeyState.ACTIVE)
                .usages(usages)
                .tenantId("default")
                .createdAt(EPOCH)
                .activatedAt(EPOCH)
                .rotationPolicy(null)
                .exportable(false)
                .usageCount(0)
                .attributes(Map.of("source", "environment"))
                .fingerprint(KeySupport.fingerprint(material))
                .build();
        return new StoredKey(descriptor, material, KeyMaterialCodec.RAW, false, Map.of());
    }

    private static ParsedName parseName(String suffix) {
        if (suffix.isEmpty()) {
            return null;
        }
        Matcher matcher = VERSION_SUFFIX.matcher(suffix);
        String idPart;
        long version;
        if (matcher.matches()) {
            idPart = matcher.group(1);
            try {
                version = Long.parseLong(matcher.group(2));
            } catch (NumberFormatException e) {
                return null;
            }
        } else {
            idPart = suffix;
            version = 1L;
        }
        if (idPart.isEmpty() || !idPart.matches("[A-Z0-9][A-Z0-9_]*")) {
            return null;
        }
        if (version < 1) {
            return null;
        }
        try {
            return new ParsedName(KeyId.of(idPart), new KeyVersion(version));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private record ParsedName(KeyId keyId, KeyVersion version) {
    }
}