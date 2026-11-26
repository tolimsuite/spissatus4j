package cn.tolim.spissatus4j.core.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import java.util.List;
import org.junit.jupiter.api.Test;

class DefaultExtensionRegistryTest {

    interface Service {
        String name();
    }

    @Test
    void registerFindAndList() {
        DefaultExtensionRegistry registry = new DefaultExtensionRegistry();
        Service one = () -> "one";
        registry.register(Service.class, "one", one);
        registry.register(Service.class, "one", one);
        assertSame(one, registry.find(Service.class, "one").orElseThrow());
        assertTrue(registry.contains(Service.class, "one"));
        assertEquals(List.of("one"), List.copyOf(registry.ids(Service.class)));
        assertEquals(1, registry.all(Service.class).size());
        assertFalse(registry.find(Service.class, "missing").isPresent());
    }

    @Test
    void duplicateIdWithDifferentImplementationIsRejected() {
        DefaultExtensionRegistry registry = new DefaultExtensionRegistry();
        registry.register(Service.class, "one", () -> "one");
        assertThrows(ConfigurationException.class,
                () -> registry.register(Service.class, "one", () -> "other"));
    }

    @Test
    void typesAreIsolated() {
        DefaultExtensionRegistry registry = new DefaultExtensionRegistry();
        registry.register(Service.class, "one", () -> "one");
        assertTrue(registry.all(String.class).isEmpty());
    }
}