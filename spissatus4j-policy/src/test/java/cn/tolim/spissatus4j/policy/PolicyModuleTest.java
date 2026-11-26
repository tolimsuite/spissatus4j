package cn.tolim.spissatus4j.policy;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.audit.AlertSink;
import cn.tolim.spissatus4j.contract.audit.AuditSink;
import cn.tolim.spissatus4j.contract.audit.MetricsRecorder;
import cn.tolim.spissatus4j.contract.crypto.RandomService;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeCodec;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.key.KeyManagerFactory;
import cn.tolim.spissatus4j.contract.key.KeyWrapper;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.policy.PolicyProvider;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyModuleTest {

    private final PolicyModule module = new PolicyModule();

    @Test
    void moduleIdentityIsStable() {
        assertEquals("policy", module.moduleId());
        assertEquals(150, module.order());
        assertEquals("false", PolicyModule.settingDefaults().get("spissatus.policy.allow-anonymous"));
        assertEquals("STANDARD", PolicyModule.settingDefaults().get("spissatus.compliance.mode"));
    }

    @Test
    void registersEngineWithSecureDefaults() {
        PolicyEngine engine = engine(Map.of());

        assertNotNull(engine);
        assertEquals("policy", engine.engineId());
        assertEquals(HealthStatus.UP, engine.health());

        assertTrue(engine.evaluate(request(Operation.ENCRYPT, TestFixtures.caller(),
                AlgorithmId.AES_GCM)).allowed());

        PolicyDecision anonymous = engine.evaluate(request(Operation.ENCRYPT,
                CallerContext.anonymous(), AlgorithmId.AES_GCM));
        assertTrue(anonymous.denied());
        assertEquals(ReasonCodes.ANONYMOUS_CALLER, anonymous.reasonCode());

        PolicyDecision md5 = engine.evaluate(request(Operation.DIGEST, TestFixtures.caller(),
                AlgorithmId.MD5));
        assertTrue(md5.denied());
        assertEquals(ReasonCodes.ALGORITHM_PROHIBITED, md5.reasonCode());
    }

    @Test
    void allowAnonymousSettingIsHonored() {
        PolicyEngine engine = engine(Map.of("spissatus.policy.allow-anonymous", "true"));

        assertTrue(engine.evaluate(request(Operation.ENCRYPT, CallerContext.anonymous(),
                AlgorithmId.AES_GCM)).allowed());
    }

    @Test
    void allowExperimentalSettingIsHonored() {
        PolicyEngine strict = engine(Map.of());
        assertTrue(strict.evaluate(request(Operation.ENCRYPT, TestFixtures.caller(),
                AlgorithmId.ML_KEM_768)).denied());

        PolicyEngine permissive = engine(Map.of("spissatus.policy.allow-experimental", "true"));
        assertTrue(permissive.evaluate(request(Operation.ENCRYPT, TestFixtures.caller(),
                AlgorithmId.ML_KEM_768)).allowed());
    }

    @Test
    void allowedCallersSettingIsHonored() {
        PolicyEngine engine = engine(Map.of("spissatus.policy.allowed-callers", "svc-a"));

        assertTrue(engine.evaluate(request(Operation.ENCRYPT, TestFixtures.caller(),
                AlgorithmId.AES_GCM)).allowed());

        PolicyDecision denied = engine.evaluate(request(Operation.ENCRYPT,
                TestFixtures.caller("svc-b", TestFixtures.TENANT, "user"), AlgorithmId.AES_GCM));
        assertTrue(denied.denied());
        assertEquals(ReasonCodes.CALLER_NOT_AUTHORIZED, denied.reasonCode());
    }

    @Test
    void tenantQuotaSettingIsHonored() {
        PolicyEngine engine = engine(Map.of("spissatus.policy.tenant-quota-per-minute", "1"));

        assertTrue(engine.evaluate(request(Operation.ENCRYPT,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "user"),
                AlgorithmId.AES_GCM)).allowed());

        PolicyDecision denied = engine.evaluate(request(Operation.ENCRYPT,
                TestFixtures.caller("svc-b", TestFixtures.TENANT, "user"), AlgorithmId.AES_GCM));
        assertTrue(denied.denied());
        assertEquals(ReasonCodes.QUOTA_EXCEEDED, denied.reasonCode());
    }

    @Test
    void denyAlgorithmsSettingIsHonored() {
        PolicyEngine engine = engine(Map.of("spissatus.policy.deny-algorithms", "AES-GCM, MD5"));

        PolicyDecision decision = engine.evaluate(request(Operation.ENCRYPT, TestFixtures.caller(),
                AlgorithmId.AES_GCM));

        assertTrue(decision.denied());
        assertEquals(ReasonCodes.ALGORITHM_PROHIBITED, decision.reasonCode());
    }

    @Test
    void allowAlgorithmsSettingActsAsWhitelist() {
        PolicyEngine engine = engine(Map.of("spissatus.policy.allow-algorithms", "SHA-256"));

        assertTrue(engine.evaluate(request(Operation.DIGEST, TestFixtures.caller(),
                AlgorithmId.SHA_256)).allowed());

        PolicyDecision decision = engine.evaluate(request(Operation.ENCRYPT, TestFixtures.caller(),
                AlgorithmId.AES_GCM));
        assertTrue(decision.denied());
        assertEquals(ReasonCodes.ALGORITHM_NOT_ALLOWED, decision.reasonCode());
    }

    @Test
    void requiredRoleSettingIsHonored() {
        PolicyEngine engine = engine(Map.of("spissatus.policy.required-role", "admin"));

        assertTrue(engine.evaluate(request(Operation.ENCRYPT,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "user"),
                AlgorithmId.AES_GCM)).denied());
        assertTrue(engine.evaluate(request(Operation.ENCRYPT,
                TestFixtures.caller("svc-a", TestFixtures.TENANT, "user", "admin"),
                AlgorithmId.AES_GCM)).allowed());
    }

    @Test
    void allowedEnvironmentsSettingIsHonored() {
        PolicyEngine engine = engine(Map.of("spissatus.policy.allowed-environments", "prod"));

        PolicyDecision denied = engine.evaluate(request(Operation.ENCRYPT, TestFixtures.caller(),
                AlgorithmId.AES_GCM));
        assertTrue(denied.denied());
        assertEquals(ReasonCodes.CALLER_NOT_AUTHORIZED, denied.reasonCode());

        CallerContext prodCaller = new CallerContext("svc-a", TestFixtures.TENANT,
                Set.of("user"), "prod", Map.of());
        assertTrue(engine.evaluate(request(Operation.ENCRYPT, prodCaller,
                AlgorithmId.AES_GCM)).allowed());
    }

    @Test
    void allowedTenantsSettingIsHonored() {
        PolicyEngine engine = engine(Map.of("spissatus.policy.allowed-tenants", TestFixtures.TENANT));

        PolicyDecision denied = engine.evaluate(request(Operation.ENCRYPT,
                TestFixtures.caller("svc-b", "tenant-b", "user"), AlgorithmId.AES_GCM));
        assertTrue(denied.denied());
        assertEquals(ReasonCodes.TENANT_MISMATCH, denied.reasonCode());

        assertTrue(engine.evaluate(request(Operation.ENCRYPT, TestFixtures.caller(),
                AlgorithmId.AES_GCM)).allowed());
    }

    @Test
    void rateLimitSettingIsHonored() {
        PolicyEngine engine = engine(Map.of("spissatus.policy.rate-limit-per-minute", "1"));
        CallerContext caller = TestFixtures.caller();

        assertTrue(engine.evaluate(request(Operation.ENCRYPT, caller, AlgorithmId.AES_GCM)).allowed());

        PolicyDecision second = engine.evaluate(request(Operation.ENCRYPT, caller,
                AlgorithmId.AES_GCM));
        assertTrue(second.denied());
        assertEquals(ReasonCodes.RATE_LIMITED, second.reasonCode());
    }

    @Test
    void gmComplianceModeIsHonored() {
        PolicyEngine engine = engine(Map.of("spissatus.compliance.mode", "GM"));

        PolicyDecision aesGcm = engine.evaluate(request(Operation.ENCRYPT, TestFixtures.caller(),
                AlgorithmId.AES_GCM));
        assertTrue(aesGcm.denied());
        assertEquals(ReasonCodes.COMPLIANCE_MODE_VIOLATION, aesGcm.reasonCode());

        assertTrue(engine.evaluate(request(Operation.ENCRYPT, TestFixtures.caller(),
                AlgorithmId.SM4_GCM)).allowed());
    }

    @Test
    void fipsComplianceModeIsHonored() {
        PolicyEngine engine = engine(Map.of("spissatus.compliance.mode", "FIPS"));

        PolicyDecision chacha = engine.evaluate(request(Operation.ENCRYPT, TestFixtures.caller(),
                AlgorithmId.CHACHA20_POLY1305));
        assertTrue(chacha.denied());
        assertEquals(ReasonCodes.COMPLIANCE_MODE_VIOLATION, chacha.reasonCode());

        assertTrue(engine.evaluate(request(Operation.ENCRYPT, TestFixtures.caller(),
                AlgorithmId.AES_GCM)).allowed());
    }

    @Test
    void invalidBooleanSettingIsRejected() {
        assertThrows(ConfigurationException.class,
                () -> module.contribute(new StubContext(Map.of(
                        "spissatus.policy.allow-anonymous", "yes"))));
    }

    @Test
    void invalidComplianceModeIsRejected() {
        assertThrows(ConfigurationException.class,
                () -> module.contribute(new StubContext(Map.of(
                        "spissatus.compliance.mode", "MODERN"))));
    }

    @Test
    void invalidAlgorithmIdentifierIsRejected() {
        assertThrows(ConfigurationException.class,
                () -> module.contribute(new StubContext(Map.of(
                        "spissatus.policy.deny-algorithms", "not a valid id!"))));
    }

    @Test
    void negativeRateLimitIsRejected() {
        assertThrows(ConfigurationException.class,
                () -> module.contribute(new StubContext(Map.of(
                        "spissatus.policy.rate-limit-per-minute", "-3"))));
    }

    @Test
    void moduleIsDiscoverableThroughServiceLoader() {
        boolean found = ServiceLoader.load(SpissatusModule.class).stream()
                .map(ServiceLoader.Provider::get)
                .anyMatch(candidate -> "policy".equals(candidate.moduleId())
                        && candidate.order() == 150);

        assertTrue(found, "PolicyModule must be registered in META-INF/services");
    }

    @Test
    void repeatedContributionProducesUsableEngine() {
        StubContext context = new StubContext(Map.of());

        module.contribute(context);
        module.contribute(context);

        assertNotNull(context.policyEngine);
        assertEquals(HealthStatus.UP, context.policyEngine.health());
    }

    private PolicyEngine engine(Map<String, String> settings) {
        StubContext context = new StubContext(settings);
        module.contribute(context);
        assertNotNull(context.policyEngine, "Module must register a policy engine");
        return context.policyEngine;
    }

    private static PolicyRequest request(Operation operation, CallerContext caller,
                                                 AlgorithmId algorithm) {
        return PolicyRequest.builder(operation, caller).algorithm(algorithm).build();
    }

    private static final class StubContext implements ModuleContext {

        private final Map<String, String> settings;
        private final Map<String, String> attributes = new HashMap<>();
        private PolicyEngine policyEngine;

        private StubContext(Map<String, String> settings) {
            this.settings = Map.copyOf(settings);
        }

        @Override
        public void registerAlgorithmProvider(AlgorithmProvider provider) {
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
            this.policyEngine = engine;
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
            return settings;
        }

        @Override
        public void attribute(String key, String value) {
            attributes.put(key, value);
        }
    }
}