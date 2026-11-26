package cn.tolim.spissatus4j.contract.spi;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Typed registry of trusted extensions. Duplicate identifiers are rejected;
 * explicit registrations override discovered registrations only when the
 * builder allows it.
 */
public interface ExtensionRegistry {

    <T> void register(Class<T> type, String id, T extension);

    <T> Optional<T> find(Class<T> type, String id);

    <T> List<T> all(Class<T> type);

    <T> boolean contains(Class<T> type, String id);

    <T> Set<String> ids(Class<T> type);
}