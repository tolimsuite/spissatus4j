package cn.tolim.spissatus4j.key;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.key.KeyManager;
import cn.tolim.spissatus4j.contract.key.KeyManagerDependencies;
import cn.tolim.spissatus4j.contract.key.KeyManagerFactory;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import cn.tolim.spissatus4j.key.manager.DefaultKeyManager;
import cn.tolim.spissatus4j.key.support.TestSupport.MutableClock;
import cn.tolim.spissatus4j.key.support.TestSupport.RecordingAuditTrail;
import cn.tolim.spissatus4j.key.support.TestSupport.RecordingModuleContext;
import cn.tolim.spissatus4j.key.support.TestSupport.StubPolicyEngine;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import org.junit.jupiter.api.Test;

class KeyModuleTest {

    @Test
    void isDiscoverableThroughServiceLoader() {
        List<SpissatusModule> modules = ServiceLoader.load(SpissatusModule.class).stream()
                .map(ServiceLoader.Provider::get)
                .filter(module -> module instanceof KeyModule)
                .toList();
        assertEquals(1, modules.size());
        SpissatusModule module = modules.get(0);
        assertEquals("key", module.moduleId());
        assertEquals(200, module.order());
        assertTrue(module.selfCheck().passed());
    }

    @Test
    void contributesKeyManagerFactory() {
        KeyModule module = new KeyModule();
        RecordingModuleContext context = new RecordingModuleContext();
        module.contribute(context);
        assertEquals(1, context.keyManagerFactories().size());
        KeyManagerFactory factory = context.keyManagerFactories().get(0);
        assertEquals("default-key-manager", factory.factoryId());

        KeyManager manager = factory.create(new KeyManagerDependencies(
                new StubPolicyEngine(), new RecordingAuditTrail(),
                new MutableClock(Instant.parse("2026-05-01T00:00:00Z")), List.of(),
                Map.of("spissatus.key.provider", "memory")));
        assertInstanceOf(DefaultKeyManager.class, manager);
        assertEquals("memory", ((DefaultKeyManager) manager).providerId());
        manager.close();

        module.contribute(context);
        assertEquals(2, context.keyManagerFactories().size());
        assertEquals("default-key-manager",
                context.keyManagerFactories().get(1).factoryId());
    }
}