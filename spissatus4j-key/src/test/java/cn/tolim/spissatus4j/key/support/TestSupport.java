package cn.tolim.spissatus4j.key.support;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.KeyUsage;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.audit.AlertSink;
import cn.tolim.spissatus4j.contract.audit.AuditChainStatus;
import cn.tolim.spissatus4j.contract.audit.AuditEvent;
import cn.tolim.spissatus4j.contract.audit.AuditEventType;
import cn.tolim.spissatus4j.contract.audit.AuditTrail;
import cn.tolim.spissatus4j.contract.audit.AuditSink;
import cn.tolim.spissatus4j.contract.audit.MetricsRecorder;
import cn.tolim.spissatus4j.contract.crypto.RandomService;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeCodec;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.key.KeyManagerFactory;
import cn.tolim.spissatus4j.contract.key.KeyWrapper;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.policy.PolicyProvider;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.SecretKey;

/** Shared deterministic test doubles. */
public final class TestSupport {

    private TestSupport() {
    }

    public static CallerContext caller() {
        return CallerContext.of("test-service", "default", Set.of("crypto-user"));
    }

    public static CallerContext caller(String tenantId, Set<String> roles) {
        return CallerContext.of("test-service", tenantId, roles);
    }

    /** Recording audit trail; never refuses writes. */
    public static final class RecordingAuditTrail implements AuditTrail {

        private final List<AuditEvent> events = new CopyOnWriteArrayList<>();

        @Override
        public AuditEvent append(AuditEvent event) {
            events.add(event);
            return event;
        }

        @Override
        public AuditChainStatus verify() {
            return AuditChainStatus.intact(events.size(), "test");
        }

        @Override
        public List<AuditEvent> recent(int limit) {
            int from = Math.max(0, events.size() - Math.max(0, limit));
            return List.copyOf(events.subList(from, events.size()));
        }

        @Override
        public HealthStatus health() {
            return HealthStatus.UP;
        }

        @Override
        public void close() {
        }

        public List<AuditEvent> events() {
            return List.copyOf(events);
        }

        public boolean has(AuditEventType type) {
            return events.stream().anyMatch(event -> event.type() == type);
        }

        public AuditEvent first(AuditEventType type) {
            return events.stream().filter(event -> event.type() == type).findFirst().orElse(null);
        }
    }

    /** Policy engine with a configurable outcome or an outage mode. */
    public static final class StubPolicyEngine implements PolicyEngine {

        private final List<PolicyRequest> requests = new CopyOnWriteArrayList<>();
        private volatile PolicyDecision.Outcome outcome = PolicyDecision.Outcome.ALLOW;
        private volatile boolean unavailable;

        public void setOutcome(PolicyDecision.Outcome value) {
            this.outcome = value;
        }

        public void setUnavailable(boolean value) {
            this.unavailable = value;
        }

        public List<PolicyRequest> requests() {
            return List.copyOf(requests);
        }

        public long count(Operation operation) {
            return requests.stream().filter(request -> request.operation() == operation).count();
        }

        @Override
        public String engineId() {
            return "stub-policy";
        }

        @Override
        public PolicyDecision evaluate(PolicyRequest request) {
            requests.add(request);
            if (unavailable) {
                throw new IllegalStateException("policy source unavailable");
            }
            return switch (outcome) {
                case ALLOW -> PolicyDecision.allow("stub-policy");
                case WARN -> PolicyDecision.warn("STUB_WARNING", "stub warning", "stub-policy");
                case DENY -> PolicyDecision.deny("STUB_DENY", "stub denial", "stub-policy");
            };
        }

        @Override
        public HealthStatus health() {
            return unavailable ? HealthStatus.DOWN : HealthStatus.UP;
        }
    }

    /** Manually advanced clock. */
    public static final class MutableClock extends Clock {

        private volatile Instant instant;
        private final ZoneId zone;

        public MutableClock(Instant instant) {
            this(instant, ZoneOffset.UTC);
        }

        public MutableClock(Instant instant, ZoneId zone) {
            this.instant = instant;
            this.zone = zone;
        }

        public void advance(Duration duration) {
            this.instant = this.instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId newZone) {
            return new MutableClock(instant, newZone);
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }

    /** Reversible byte transform used to prove a custom wrapper was selected. */
    public static final class RecordingKeyWrapper implements KeyWrapper {

        private final String wrapperId;
        private final Set<AlgorithmId> algorithms;
        private final AtomicInteger wraps = new AtomicInteger();
        private final AtomicInteger unwraps = new AtomicInteger();

        public RecordingKeyWrapper(String wrapperId, Set<AlgorithmId> algorithms) {
            this.wrapperId = wrapperId;
            this.algorithms = Set.copyOf(algorithms);
        }

        public int wrapCount() {
            return wraps.get();
        }

        public int unwrapCount() {
            return unwraps.get();
        }

        @Override
        public String wrapperId() {
            return wrapperId;
        }

        @Override
        public Set<AlgorithmId> algorithms() {
            return algorithms;
        }

        @Override
        public byte[] wrap(PublicKey kek, byte[] dek) {
            wraps.incrementAndGet();
            return reverse(dek);
        }

        @Override
        public byte[] unwrap(PrivateKey kek, byte[] wrappedDek) {
            unwraps.incrementAndGet();
            return reverse(wrappedDek);
        }

        @Override
        public byte[] wrap(SecretKey kek, byte[] dek) {
            wraps.incrementAndGet();
            return reverse(dek);
        }

        @Override
        public byte[] unwrap(SecretKey kek, byte[] wrappedDek) {
            unwraps.incrementAndGet();
            return reverse(wrappedDek);
        }

        private static byte[] reverse(byte[] value) {
            byte[] result = new byte[value.length];
            for (int i = 0; i < value.length; i++) {
                result[i] = value[value.length - 1 - i];
            }
            return result;
        }
    }

    /** Module context that records registrations. */
    public static final class RecordingModuleContext implements ModuleContext {

        private final List<KeyManagerFactory> keyManagerFactories = new ArrayList<>();
        private final Map<String, String> settings = new LinkedHashMap<>();
        private final Map<String, String> attributes = new LinkedHashMap<>();

        public List<KeyManagerFactory> keyManagerFactories() {
            return List.copyOf(keyManagerFactories);
        }

        @Override
        public void registerAlgorithmProvider(AlgorithmProvider provider) {
        }

        @Override
        public void registerKeyProvider(KeyProvider provider) {
        }

        @Override
        public void registerKeyManagerFactory(KeyManagerFactory factory) {
            keyManagerFactories.add(factory);
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
            attributes.put(key, value);
        }
    }

    public static Set<KeyUsage> usages(KeyUsage... usages) {
        return Set.of(usages);
    }
}