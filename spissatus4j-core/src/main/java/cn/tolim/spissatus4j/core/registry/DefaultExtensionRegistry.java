package cn.tolim.spissatus4j.core.registry;

import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.spi.ExtensionRegistry;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Thread-safe typed extension registry. Registering the same id with a
 * different instance is rejected; re-registering the identical instance is
 * idempotent.
 */
public final class DefaultExtensionRegistry implements ExtensionRegistry {

    private final Map<Class<?>, LinkedHashMap<String, Object>> registry = new LinkedHashMap<>();

    @Override
    public synchronized <T> void register(Class<T> type, String id, T extension) {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(extension, "extension");
        if (id.isBlank()) {
            throw new IllegalArgumentException("Extension id must not be blank");
        }
        LinkedHashMap<String, Object> entries = registry.computeIfAbsent(type, ignored -> new LinkedHashMap<>());
        Object existing = entries.get(id);
        if (existing == extension) {
            return;
        }
        if (existing != null) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Duplicate extension registration for type " + type.getSimpleName() + " and id " + id);
        }
        entries.put(id, extension);
    }

    @Override
    @SuppressWarnings("unchecked")
    public synchronized <T> Optional<T> find(Class<T> type, String id) {
        Map<String, Object> entries = registry.get(type);
        if (entries == null) {
            return Optional.empty();
        }
        return Optional.ofNullable((T) entries.get(id));
    }

    @Override
    @SuppressWarnings("unchecked")
    public synchronized <T> List<T> all(Class<T> type) {
        Map<String, Object> entries = registry.get(type);
        if (entries == null) {
            return List.of();
        }
        List<T> result = new ArrayList<>(entries.size());
        for (Object value : entries.values()) {
            result.add((T) value);
        }
        return List.copyOf(result);
    }

    @Override
    public synchronized <T> boolean contains(Class<T> type, String id) {
        Map<String, Object> entries = registry.get(type);
        return entries != null && entries.containsKey(id);
    }

    @Override
    public synchronized <T> Set<String> ids(Class<T> type) {
        Map<String, Object> entries = registry.get(type);
        return entries == null ? Set.of() : Set.copyOf(entries.keySet());
    }
}