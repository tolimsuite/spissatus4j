package cn.tolim.spissatus4j.bc;

import cn.tolim.spissatus4j.contract.audit.AlertSink;
import cn.tolim.spissatus4j.contract.audit.AuditSink;
import cn.tolim.spissatus4j.contract.audit.MetricsRecorder;
import cn.tolim.spissatus4j.contract.crypto.RandomService;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeCodec;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.key.KeyManagerFactory;
import cn.tolim.spissatus4j.contract.key.KeyWrapper;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.policy.PolicyProvider;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Recording {@link ModuleContext} stub used by module tests. */
final class TestModuleContext implements ModuleContext {

    private final Map<String, String> settings;
    private final Map<String, List<Object>> registrations = new LinkedHashMap<>();
    private final Map<String, String> attributes = new LinkedHashMap<>();

    TestModuleContext() {
        this(Map.of());
    }

    TestModuleContext(Map<String, String> settings) {
        this.settings = Map.copyOf(Objects.requireNonNull(settings, "settings"));
    }

    private void record(String kind, Object value) {
        registrations.computeIfAbsent(kind, key -> new ArrayList<>())
                .add(Objects.requireNonNull(value, "value"));
    }

    List<AlgorithmProvider> algorithmProviders() {
        return registrations.getOrDefault("algorithmProvider", List.of()).stream()
                .map(AlgorithmProvider.class::cast)
                .toList();
    }

    Map<String, List<Object>> registrations() {
        return Collections.unmodifiableMap(registrations);
    }

    boolean hasAnyRegistration() {
        return !registrations.isEmpty();
    }

    Map<String, String> attributes() {
        return Collections.unmodifiableMap(attributes);
    }

    @Override
    public void registerAlgorithmProvider(AlgorithmProvider provider) {
        record("algorithmProvider", provider);
    }

    @Override
    public void registerKeyProvider(KeyProvider provider) {
        record("keyProvider", provider);
    }

    @Override
    public void registerKeyManagerFactory(KeyManagerFactory factory) {
        record("keyManagerFactory", factory);
    }

    @Override
    public void registerEnvelopeCodec(EnvelopeCodec codec) {
        record("envelopeCodec", codec);
    }

    @Override
    public void registerEnvelopeService(EnvelopeService service) {
        record("envelopeService", service);
    }

    @Override
    public void registerStreamCipherService(StreamCipherService service) {
        record("streamCipherService", service);
    }

    @Override
    public void registerRandomService(RandomService service) {
        record("randomService", service);
    }

    @Override
    public void registerPolicyEngine(PolicyEngine engine) {
        record("policyEngine", engine);
    }

    @Override
    public void registerPolicyProvider(PolicyProvider provider) {
        record("policyProvider", provider);
    }

    @Override
    public void registerAuditSink(AuditSink sink) {
        record("auditSink", sink);
    }

    @Override
    public void registerMetricsRecorder(MetricsRecorder recorder) {
        record("metricsRecorder", recorder);
    }

    @Override
    public void registerAlertSink(AlertSink sink) {
        record("alertSink", sink);
    }

    @Override
    public void registerKeyWrapper(KeyWrapper wrapper) {
        record("keyWrapper", wrapper);
    }

    @Override
    public void register(Class<?> type, String id, Object extension) {
        record("extension:" + type.getName() + ":" + id, extension);
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
        attributes.put(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
    }
}