package cn.tolim.spissatus4j.gm;

import cn.tolim.spissatus4j.contract.audit.AlertSink;
import cn.tolim.spissatus4j.contract.audit.AuditSink;
import cn.tolim.spissatus4j.contract.audit.MetricsRecorder;
import cn.tolim.spissatus4j.contract.crypto.RandomService;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeCodec;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyManagerFactory;
import cn.tolim.spissatus4j.contract.key.KeyWrapper;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.policy.PolicyProvider;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import cn.tolim.spissatus4j.gm.provider.GmAlgorithmProvider;
import cn.tolim.spissatus4j.gm.sm2.Sm2KeyWrapper;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GmModuleTest {

    @Test
    void moduleMetadata() {
        GmModule module = new GmModule();
        assertEquals("gm", module.moduleId());
        assertEquals(260, module.order());
    }

    @Test
    void serviceLoaderDiscoversModule() {
        boolean found = false;
        for (SpissatusModule module : ServiceLoader.load(SpissatusModule.class)) {
            if ("gm".equals(module.moduleId())) {
                assertInstanceOf(GmModule.class, module);
                found = true;
            }
        }
        assertTrue(found, "GmModule must be registered in META-INF/services");
    }

    @Test
    void contributeRegistersProviderAndKeyWrapper() {
        StubContext context = StubContext.empty();
        new GmModule().contribute(context);

        assertEquals(1, context.algorithmProviders.size());
        assertInstanceOf(GmAlgorithmProvider.class, context.algorithmProviders.get(0));
        assertEquals(1, context.keyWrappers.size());
        assertInstanceOf(Sm2KeyWrapper.class, context.keyWrappers.get(0));
        assertEquals("true", context.attributes.get(GmModule.ATTRIBUTE_ENABLED));
        assertTrue(List.of(GmModule.ATTRIBUTE_BC_PROVIDER_REGISTERED,
                        GmModule.ATTRIBUTE_BC_PROVIDER_PRESENT)
                .contains(context.attributes.get(GmModule.ATTRIBUTE_BC_PROVIDER)));
        assertEquals("gm", context.attributes.get("gm.provider-id"));
        assertEquals("sm2", context.attributes.get("gm.wrapper-id"));
    }

    @Test
    void disabledSettingSkipsRegistration() {
        StubContext context = StubContext.of(Map.of(GmModule.SETTING_ENABLED, "false"));
        new GmModule().contribute(context);

        assertTrue(context.algorithmProviders.isEmpty());
        assertTrue(context.keyWrappers.isEmpty());
        assertEquals("false", context.attributes.get(GmModule.ATTRIBUTE_ENABLED));
        assertNull(context.attributes.get(GmModule.ATTRIBUTE_BC_PROVIDER));
    }

    @Test
    void enabledSettingAcceptsBooleanAliases() {
        StubContext context = StubContext.of(Map.of(GmModule.SETTING_ENABLED, "no"));
        new GmModule().contribute(context);
        assertTrue(context.algorithmProviders.isEmpty());
    }

    @Test
    void contributeIsIdempotentPerContext() {
        StubContext context = StubContext.empty();
        GmModule module = new GmModule();
        module.contribute(context);
        module.contribute(context);
        module.contribute(context);

        assertEquals(1, context.algorithmProviders.size());
        assertEquals(1, context.keyWrappers.size());
    }

    @Test
    void fipsSettingSkipsBouncyCastleProviderRegistration() {
        StubContext context = StubContext.of(Map.of(GmModule.SETTING_FIPS_ENABLED, "true"));
        new GmModule().contribute(context);

        assertEquals(GmModule.ATTRIBUTE_BC_PROVIDER_SKIPPED_FIPS,
                context.attributes.get(GmModule.ATTRIBUTE_BC_PROVIDER));
        assertEquals(1, context.algorithmProviders.size());
        assertEquals(1, context.keyWrappers.size());
    }

    @Test
    void invalidBooleanSettingIsRejected() {
        StubContext context = StubContext.of(Map.of(GmModule.SETTING_ENABLED, "sometimes"));
        ConfigurationException exception =
                assertThrows(ConfigurationException.class, () -> new GmModule().contribute(context));
        assertEquals(ErrorCode.CONFIGURATION_INVALID, exception.errorCode());
        assertFalse(exception.getMessage().contains("sometimes"));
    }

    @Test
    void moduleSelfCheckIsUpAndPrefixed() {
        GmModule module = new GmModule();
        module.contribute(StubContext.empty());

        SelfCheckReport report = module.selfCheck();
        assertTrue(report.passed());
        assertEquals(6, report.checks().size());
        for (var check : report.checks()) {
            assertTrue(check.checkId().startsWith("gm."));
        }
    }

    @Test
    void disabledModuleSelfCheckIsEmpty() {
        GmModule module = new GmModule();
        module.contribute(StubContext.of(Map.of(GmModule.SETTING_ENABLED, "false")));

        SelfCheckReport report = module.selfCheck();

        assertTrue(report.passed());
        assertTrue(report.checks().isEmpty(),
                "a disabled module must not run GM known-answer checks");
    }

    @Test
    void notContributedModuleSelfCheckIsEmpty() {
        SelfCheckReport report = new GmModule().selfCheck();

        assertTrue(report.passed());
        assertTrue(report.checks().isEmpty(),
                "a module that never contributed must not run GM known-answer checks");
    }

    private static final class StubContext implements ModuleContext {

        private final Map<String, String> settings;
        private final Map<String, String> attributes = new LinkedHashMap<>();
        private final List<AlgorithmProvider> algorithmProviders = new ArrayList<>();
        private final List<KeyWrapper> keyWrappers = new ArrayList<>();

        private StubContext(Map<String, String> settings) {
            this.settings = Map.copyOf(settings);
        }

        static StubContext empty() {
            return new StubContext(Map.of());
        }

        static StubContext of(Map<String, String> settings) {
            return new StubContext(settings);
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
        }

        @Override
        public void registerRandomService(RandomService service) {
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
            keyWrappers.add(wrapper);
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
            return settings;
        }

        @Override
        public void attribute(String key, String value) {
            attributes.put(key, value);
        }
    }
}