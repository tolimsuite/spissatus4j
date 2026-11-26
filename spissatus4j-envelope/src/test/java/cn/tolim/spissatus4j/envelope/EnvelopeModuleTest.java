package cn.tolim.spissatus4j.envelope;

import static cn.tolim.spissatus4j.envelope.TestEnvelopes.aesGcmEnvelope;
import static cn.tolim.spissatus4j.envelope.TestEnvelopes.assertErrorCode;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.audit.AlertSink;
import cn.tolim.spissatus4j.contract.audit.AuditSink;
import cn.tolim.spissatus4j.contract.audit.MetricsRecorder;
import cn.tolim.spissatus4j.contract.crypto.RandomService;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeCodec;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyManagerFactory;
import cn.tolim.spissatus4j.contract.key.KeyWrapper;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.policy.PolicyProvider;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import cn.tolim.spissatus4j.envelope.internal.DefaultEnvelopeService;
import cn.tolim.spissatus4j.envelope.internal.DefaultVersionPolicy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class EnvelopeModuleTest {

    @Test
    void moduleMetadataIsStable() {
        EnvelopeModule module = new EnvelopeModule();
        assertEquals("envelope", module.moduleId());
        assertEquals(300, module.order());
    }

    @Test
    void contributesServiceAndBothCodecs() {
        FakeContext context = new FakeContext(Map.of());
        new EnvelopeModule().contribute(context);
        assertEquals(2, context.codecs.size());
        assertNotNull(context.service);
        Set<String> formatIds = context.codecs.stream()
                .map(EnvelopeCodec::formatId)
                .collect(Collectors.toSet());
        assertEquals(Set.of("TLV", "JSON"), formatIds);
        for (EnvelopeFormat format : EnvelopeFormat.values()) {
            assertNotNull(context.service.decode(context.service.encode(aesGcmEnvelope(), format)));
        }
    }

    @Test
    void contributionIsIdempotent() {
        FakeContext context = new FakeContext(Map.of());
        EnvelopeModule module = new EnvelopeModule();
        module.contribute(context);
        EnvelopeService first = context.service;
        module.contribute(context);
        assertEquals(2, context.codecs.size());
        assertEquals(first, context.service);
    }

    @Test
    void maxBytesSettingIsHonored() {
        FakeContext context = new FakeContext(Map.of(EnvelopeModule.MAX_BYTES_SETTING, "64"));
        new EnvelopeModule().contribute(context);
        assertErrorCode(ErrorCode.ENVELOPE_VALIDATION_FAILED,
                () -> context.service.encode(aesGcmEnvelope(), EnvelopeFormat.TLV));

        byte[] encoded = new DefaultEnvelopeService()
                .encode(aesGcmEnvelope(), EnvelopeFormat.TLV);
        assertTrue(encoded.length > 64);
        assertErrorCode(ErrorCode.ENVELOPE_MALFORMED, () -> context.service.decode(encoded));
    }

    @Test
    void invalidMaxBytesSettingIsRejected() {
        for (String value : List.of("nope", "0", "-1", "999999999999999")) {
            FakeContext context = new FakeContext(Map.of(EnvelopeModule.MAX_BYTES_SETTING, value));
            ConfigurationException exception = assertThrows(ConfigurationException.class,
                    () -> new EnvelopeModule().contribute(context));
            assertEquals(ErrorCode.CONFIGURATION_INVALID, exception.errorCode());
        }
    }

    @Test
    void moduleIsDiscoverableThroughServiceLoader() {
        boolean found = ServiceLoader.load(SpissatusModule.class).stream()
                .map(ServiceLoader.Provider::get)
                .anyMatch(module -> module instanceof EnvelopeModule
                        && "envelope".equals(module.moduleId()));
        assertTrue(found, "EnvelopeModule must be registered in META-INF/services");
    }

    @Test
    void defaultVersionPolicyBehavior() {
        DefaultVersionPolicy policy = new DefaultVersionPolicy();
        assertEquals(2, policy.currentVersion());
        assertTrue(policy.isSupported(1));
        assertTrue(policy.isSupported(2));
        assertFalse(policy.isSupported(0));
        assertFalse(policy.isSupported(3));
        assertTrue(policy.migrationHint(2).contains("no migration"));
        assertTrue(policy.migrationHint(1).contains("unauthenticated"));
        assertTrue(policy.migrationHint(1).contains("unified API"));
        assertFalse(policy.migrationHint(0).isEmpty());
        assertFalse(policy.migrationHint(3).isEmpty());
    }

    @Test
    void moduleHasNoSelfCheckFailures() {
        assertTrue(new EnvelopeModule().selfCheck().passed());
    }

    private static final class FakeContext implements ModuleContext {

        private final Map<String, String> settings;
        private final Map<String, String> attributes = new HashMap<>();
        private final List<EnvelopeCodec> codecs = new ArrayList<>();
        private EnvelopeService service;

        private FakeContext(Map<String, String> settings) {
            this.settings = settings;
        }

        @Override
        public void registerEnvelopeCodec(EnvelopeCodec codec) {
            boolean duplicate = codecs.stream()
                    .anyMatch(existing -> existing.formatId().equalsIgnoreCase(codec.formatId()));
            if (duplicate) {
                throw new IllegalStateException("Duplicate envelope codec");
            }
            codecs.add(codec);
        }

        @Override
        public void registerEnvelopeService(EnvelopeService envelopeService) {
            if (service != null) {
                throw new IllegalStateException("Duplicate envelope service");
            }
            this.service = envelopeService;
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

        @Override
        public void registerAlgorithmProvider(AlgorithmProvider provider) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void registerKeyProvider(KeyProvider provider) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void registerKeyManagerFactory(KeyManagerFactory factory) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void registerStreamCipherService(StreamCipherService streamCipherService) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void registerRandomService(RandomService randomService) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void registerPolicyEngine(PolicyEngine engine) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void registerPolicyProvider(PolicyProvider provider) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void registerAuditSink(AuditSink sink) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void registerMetricsRecorder(MetricsRecorder recorder) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void registerAlertSink(AlertSink sink) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void registerKeyWrapper(KeyWrapper wrapper) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void register(Class<?> type, String id, Object extension) {
            throw new UnsupportedOperationException();
        }
    }
}