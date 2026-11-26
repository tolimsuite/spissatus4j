package cn.tolim.spissatus4j.key.provider;

import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import cn.tolim.spissatus4j.contract.spi.StoredKey;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;

/**
 * Process-local key storage.
 *
 * <p>Material is never encrypted at rest here because the provider has no
 * persistent storage; the manager records {@code encrypted=false} for these
 * records. The provider never logs material.</p>
 */
public final class InMemoryKeyProvider implements KeyProvider {

    public static final String PROVIDER_ID = "memory";

    private final ConcurrentHashMap<KeyId, ConcurrentSkipListMap<Long, StoredKey>> keys =
            new ConcurrentHashMap<>();

    @Override
    public String providerId() {
        return PROVIDER_ID;
    }

    @Override
    public Optional<StoredKey> load(KeyId keyId, KeyVersion version) {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(version, "version");
        ConcurrentSkipListMap<Long, StoredKey> versions = keys.get(keyId);
        if (versions == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(versions.get(version.value()));
    }

    @Override
    public void save(StoredKey storedKey) {
        Objects.requireNonNull(storedKey, "storedKey");
        KeyId keyId = storedKey.descriptor().keyId();
        long version = storedKey.descriptor().version().value();
        keys.compute(keyId, (ignored, versions) -> {
            ConcurrentSkipListMap<Long, StoredKey> target =
                    versions == null ? new ConcurrentSkipListMap<>() : versions;
            target.put(version, storedKey);
            return target;
        });
    }

    @Override
    public boolean delete(KeyId keyId, KeyVersion version) {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(version, "version");
        boolean[] removed = {false};
        keys.computeIfPresent(keyId, (ignored, versions) -> {
            removed[0] = versions.remove(version.value()) != null;
            return versions.isEmpty() ? null : versions;
        });
        return removed[0];
    }

    @Override
    public List<StoredKey> list(String tenantId) {
        List<StoredKey> result = new ArrayList<>();
        for (ConcurrentSkipListMap<Long, StoredKey> versions : keys.values()) {
            for (StoredKey storedKey : versions.values()) {
                if (tenantId == null || tenantId.equals(storedKey.descriptor().tenantId())) {
                    result.add(storedKey);
                }
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
        keys.clear();
    }
}