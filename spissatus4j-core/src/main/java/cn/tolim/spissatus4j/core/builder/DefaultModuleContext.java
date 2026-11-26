package cn.tolim.spissatus4j.core.builder;

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
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** ModuleContext implementation enforcing duplicate-registration rules. */
final class DefaultModuleContext implements ModuleContext {

    private final ModuleContributions contributions;

    DefaultModuleContext(ModuleContributions contributions) {
        this.contributions = Objects.requireNonNull(contributions, "contributions");
    }

    @Override
    public void registerAlgorithmProvider(AlgorithmProvider provider) {
        Objects.requireNonNull(provider, "provider");
        registerById(contributions.algorithmProviders, provider.providerId(), provider, "algorithm provider");
    }

    @Override
    public void registerKeyProvider(KeyProvider provider) {
        Objects.requireNonNull(provider, "provider");
        registerById(contributions.keyProviders, provider.providerId(), provider, "key provider");
    }

    @Override
    public void registerKeyManagerFactory(KeyManagerFactory factory) {
        Objects.requireNonNull(factory, "factory");
        registerById(contributions.keyManagerFactories, factory.factoryId(), factory, "key manager factory");
    }

    @Override
    public void registerEnvelopeCodec(EnvelopeCodec codec) {
        Objects.requireNonNull(codec, "codec");
        for (EnvelopeCodec existing : contributions.envelopeCodecs) {
            if (existing == codec) {
                return;
            }
            if (existing.formatId().equalsIgnoreCase(codec.formatId())) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Duplicate envelope codec: " + codec.formatId());
            }
        }
        contributions.envelopeCodecs.add(codec);
    }

    @Override
    public void registerEnvelopeService(EnvelopeService service) {
        contributions.envelopeService = single(contributions.envelopeService, service, "envelope service");
    }

    @Override
    public void registerStreamCipherService(StreamCipherService service) {
        contributions.streamCipherService = single(contributions.streamCipherService, service,
                "stream cipher service");
    }

    @Override
    public void registerRandomService(RandomService service) {
        contributions.randomService = single(contributions.randomService, service, "random service");
    }

    @Override
    public void registerPolicyEngine(PolicyEngine engine) {
        contributions.policyEngine = single(contributions.policyEngine, engine, "policy engine");
    }

    @Override
    public void registerPolicyProvider(PolicyProvider provider) {
        Objects.requireNonNull(provider, "provider");
        for (PolicyProvider existing : contributions.policyProviders) {
            if (existing == provider) {
                return;
            }
            if (existing.providerId().equals(provider.providerId())) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Duplicate policy provider: " + provider.providerId());
            }
        }
        contributions.policyProviders.add(provider);
    }

    @Override
    public void registerAuditSink(AuditSink sink) {
        Objects.requireNonNull(sink, "sink");
        for (AuditSink existing : contributions.auditSinks) {
            if (existing == sink) {
                return;
            }
            if (existing.sinkId().equals(sink.sinkId())) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Duplicate audit sink: " + sink.sinkId());
            }
        }
        contributions.auditSinks.add(sink);
    }

    @Override
    public void registerMetricsRecorder(MetricsRecorder recorder) {
        contributions.metricsRecorder = single(contributions.metricsRecorder, recorder, "metrics recorder");
    }

    @Override
    public void registerAlertSink(AlertSink sink) {
        Objects.requireNonNull(sink, "sink");
        for (AlertSink existing : contributions.alertSinks) {
            if (existing == sink) {
                return;
            }
            if (existing.sinkId().equals(sink.sinkId())) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Duplicate alert sink: " + sink.sinkId());
            }
        }
        contributions.alertSinks.add(sink);
    }

    @Override
    public void registerKeyWrapper(KeyWrapper wrapper) {
        Objects.requireNonNull(wrapper, "wrapper");
        for (KeyWrapper existing : contributions.keyWrappers) {
            if (existing == wrapper) {
                return;
            }
            if (existing.wrapperId().equals(wrapper.wrapperId())) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Duplicate key wrapper: " + wrapper.wrapperId());
            }
        }
        contributions.keyWrappers.add(wrapper);
    }

    @Override
    @SuppressWarnings({"unchecked", "rawtypes"})
    public void register(Class<?> type, String id, Object extension) {
        cn.tolim.spissatus4j.contract.spi.ExtensionRegistry raw = contributions.extensionRegistry;
        raw.register((Class) type, id, extension);
    }

    @Override
    public Optional<String> setting(String key) {
        return Optional.ofNullable(contributions.settings.get(key));
    }

    @Override
    public Map<String, String> settings() {
        return Map.copyOf(contributions.settings);
    }

    @Override
    public void attribute(String key, String value) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(value, "value");
        String previous = contributions.attributes.putIfAbsent(key, value);
        if (previous != null && !previous.equals(value)) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Conflicting module attribute: " + key);
        }
    }

    private static <T> void registerById(Map<String, T> target, String id, T value, String kind) {
        if (id == null || id.isBlank()) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID, "Blank " + kind + " id");
        }
        T existing = target.get(id);
        if (existing == value) {
            return;
        }
        if (existing != null) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Duplicate " + kind + " id: " + id);
        }
        target.put(id, value);
    }

    private static <T> T single(T existing, T value, String kind) {
        Objects.requireNonNull(value, kind);
        if (existing == null || existing == value) {
            return value;
        }
        throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                "Multiple modules contributed a " + kind);
    }
}