package cn.tolim.spissatus4j.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.audit.AlertSink;
import cn.tolim.spissatus4j.contract.audit.AuditSink;
import cn.tolim.spissatus4j.contract.audit.MetricsRecorder;
import cn.tolim.spissatus4j.contract.crypto.RandomService;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeCodec;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.key.KeyManagerFactory;
import cn.tolim.spissatus4j.contract.key.KeyWrapper;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.policy.PolicyProvider;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import cn.tolim.spissatus4j.crypto.internal.JcaAlgorithmProvider;
import cn.tolim.spissatus4j.crypto.random.SecureRandomService;
import cn.tolim.spissatus4j.crypto.stream.AeadStreamCipherService;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import org.junit.jupiter.api.Test;

class CryptoModuleTest {

    @Test
    void moduleIdentity() {
        CryptoModule module = new CryptoModule();
        assertEquals("crypto", module.moduleId());
        assertEquals(100, module.order());
    }

    @Test
    void contributeRegistersProviderRandomAndStream() {
        RecordingContext context = new RecordingContext(Map.of());
        new CryptoModule().contribute(context);

        assertEquals(1, context.algorithmProviders.size());
        assertInstanceOf(JcaAlgorithmProvider.class, context.algorithmProviders.getFirst());
        assertEquals("jca", context.algorithmProviders.getFirst().providerId());
        assertInstanceOf(SecureRandomService.class, context.randomService);
        assertInstanceOf(AeadStreamCipherService.class, context.streamCipherService);
        assertEquals("SPISSATUS-AEAD-STREAM-1", context.streamCipherService.formatId());
    }

    @Test
    void settingDisablesJcaProvider() {
        RecordingContext context = new RecordingContext(
                Map.of("spissatus.crypto.jca.enabled", "false"));
        new CryptoModule().contribute(context);
        assertTrue(context.algorithmProviders.isEmpty());
        assertNotNull(context.randomService);
        assertNotNull(context.streamCipherService);
    }

    @Test
    void settingDisablesStreamService() {
        RecordingContext context = new RecordingContext(
                Map.of("spissatus.crypto.stream.enabled", "false"));
        new CryptoModule().contribute(context);
        assertEquals(1, context.algorithmProviders.size());
        assertNotNull(context.randomService);
        assertNull(context.streamCipherService);
    }

    @Test
    void settingsAreCaseInsensitiveAndDefaultToEnabled() {
        RecordingContext context = new RecordingContext(
                Map.of("spissatus.crypto.jca.enabled", " FALSE ",
                        "spissatus.crypto.stream.enabled", "true"));
        new CryptoModule().contribute(context);
        assertTrue(context.algorithmProviders.isEmpty());
        assertNotNull(context.streamCipherService);
    }

    @Test
    void contributeIsIdempotent() {
        RecordingContext context = new RecordingContext(Map.of());
        CryptoModule module = new CryptoModule();
        module.contribute(context);
        module.contribute(context);
        module.contribute(context);
        assertEquals(1, context.algorithmProviders.size());
        assertEquals(1, context.randomRegistrations);
        assertEquals(1, context.streamRegistrations);
    }

    @Test
    void selfCheckAggregatesProviderChecks() {
        SelfCheckReport report = new CryptoModule().selfCheck();
        assertEquals(HealthStatus.UP, report.overall(), () -> report.failures().toString());
        assertTrue(report.checks().stream().anyMatch(c -> c.checkId().startsWith("crypto.")));
    }

    @Test
    void serviceLoaderDiscoversCryptoModule() {
        boolean found = ServiceLoader.load(SpissatusModule.class).stream()
                .map(ServiceLoader.Provider::get)
                .anyMatch(module -> "crypto".equals(module.moduleId()));
        assertTrue(found, "CryptoModule must be registered in META-INF/services");
    }

    private static final class RecordingContext implements ModuleContext {

        private final Map<String, String> settings;
        private final List<AlgorithmProvider> algorithmProviders = new ArrayList<>();
        private RandomService randomService;
        private StreamCipherService streamCipherService;
        private int randomRegistrations;
        private int streamRegistrations;

        RecordingContext(Map<String, String> settings) {
            this.settings = new HashMap<>(settings);
        }

        @Override
        public void registerAlgorithmProvider(AlgorithmProvider provider) {
            algorithmProviders.add(provider);
        }

        @Override
        public void registerKeyProvider(KeyProvider provider) {
        }

        @Override
        public void registerKeyManagerFactory(KeyManagerFactory factory) {
        }

        @Override
        public void registerEnvelopeCodec(EnvelopeCodec codec) {
        }

        @Override
        public void registerEnvelopeService(EnvelopeService service) {
        }

        @Override
        public void registerStreamCipherService(StreamCipherService service) {
            streamRegistrations++;
            streamCipherService = service;
        }

        @Override
        public void registerRandomService(RandomService service) {
            randomRegistrations++;
            randomService = service;
        }

        @Override
        public void registerPolicyEngine(PolicyEngine engine) {
        }

        @Override
        public void registerPolicyProvider(PolicyProvider provider) {
        }

        @Override
        public void registerAuditSink(AuditSink sink) {
        }

        @Override
        public void registerMetricsRecorder(MetricsRecorder recorder) {
        }

        @Override
        public void registerAlertSink(AlertSink sink) {
        }

        @Override
        public void registerKeyWrapper(KeyWrapper wrapper) {
        }

        @Override
        public void register(Class<?> type, String id, Object extension) {
        }

        @Override
        public Optional<String> setting(String key) {
            return Optional.ofNullable(settings.get(key));
        }

        @Override
        public Map<String, String> settings() {
            return Map.copyOf(settings);
        }

        @Override
        public void attribute(String key, String value) {
        }
    }
}
