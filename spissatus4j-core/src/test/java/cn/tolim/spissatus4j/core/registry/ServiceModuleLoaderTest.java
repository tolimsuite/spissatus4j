package cn.tolim.spissatus4j.core.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ServiceModuleLoaderTest {

    @Test
    void selfDeclaredBuiltInModuleIdIsNotTrusted() {
        ServiceModuleLoader.Result result = ServiceModuleLoader.discover(Set.of());
        assertTrue(result.modules().stream().noneMatch(module ->
                module.getClass().getName().startsWith("cn.tolim.spissatus4j.core.test")));
        assertTrue(result.rejectedModuleIds().contains("crypto"));
    }

    @Test
    void explicitTrustUsesTheImplementationClassName() {
        ServiceModuleLoader.Result byId = ServiceModuleLoader.discover(Set.of("crypto"));
        assertTrue(byId.modules().stream().noneMatch(module ->
                module.getClass().getName().startsWith("cn.tolim.spissatus4j.core.test")));
        ServiceModuleLoader.Result byClass = ServiceModuleLoader.discover(
                Set.of("cn.tolim.spissatus4j.core.test.TestUntrustedModule"));
        assertEquals(1, byClass.modules().size());
        assertTrue(byClass.modules().get(0).getClass().getName()
                .endsWith("TestUntrustedModule"));
        assertTrue(byClass.rejectedModuleIds().contains("test-fips-module"),
                "other untrusted test modules remain rejected");
    }
}
