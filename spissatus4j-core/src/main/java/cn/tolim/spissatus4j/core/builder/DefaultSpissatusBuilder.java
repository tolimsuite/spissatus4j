package cn.tolim.spissatus4j.core.builder;

import cn.tolim.spissatus4j.contract.api.Spissatus;
import cn.tolim.spissatus4j.contract.api.SpissatusBuilder;
import cn.tolim.spissatus4j.contract.audit.AlertSink;
import cn.tolim.spissatus4j.contract.audit.AuditEvent;
import cn.tolim.spissatus4j.contract.audit.AuditEventType;
import cn.tolim.spissatus4j.contract.audit.AuditOutcome;
import cn.tolim.spissatus4j.contract.audit.AuditSeverity;
import cn.tolim.spissatus4j.contract.audit.AuditSink;
import cn.tolim.spissatus4j.contract.audit.AuditTrail;
import cn.tolim.spissatus4j.contract.audit.MetricsRecorder;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.crypto.RandomService;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.SpissatusException;
import cn.tolim.spissatus4j.contract.key.KeyManager;
import cn.tolim.spissatus4j.contract.key.KeyManagerDependencies;
import cn.tolim.spissatus4j.contract.key.KeyManagerFactory;
import cn.tolim.spissatus4j.contract.key.KeyWrapper;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.runtime.FailClosedGuard;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.NonceReuseDetector;
import cn.tolim.spissatus4j.contract.runtime.RuntimeState;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckResult;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.contract.spi.ExtensionRegistry;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import cn.tolim.spissatus4j.core.audit.DefaultMetricsRecorder;
import cn.tolim.spissatus4j.core.audit.HmacChainedAuditTrail;
import cn.tolim.spissatus4j.core.audit.InMemoryAuditSink;
import cn.tolim.spissatus4j.core.audit.LoggingAlertSink;
import cn.tolim.spissatus4j.core.facade.DefaultSpissatus;
import cn.tolim.spissatus4j.core.facade.FacadeContext;
import cn.tolim.spissatus4j.core.policy.ContributorPolicyEngine;
import cn.tolim.spissatus4j.core.policy.StrictPolicyEngine;
import cn.tolim.spissatus4j.core.registry.DefaultExtensionRegistry;
import cn.tolim.spissatus4j.core.registry.ServiceModuleLoader;
import cn.tolim.spissatus4j.core.runtime.BoundedNonceReuseDetector;
import cn.tolim.spissatus4j.core.runtime.DefaultConstantTimeComparator;
import cn.tolim.spissatus4j.core.runtime.DefaultFailClosedGuard;
import cn.tolim.spissatus4j.core.runtime.DefaultSensitiveDataRedactor;
import cn.tolim.spissatus4j.core.runtime.SystemRandomService;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Default assembly implementation. Modules are ServiceLoader-discovered and
 * contribute providers/services; explicit builder calls override module
 * contributions. Startup self-check is mandatory by default and fail-closed.
 */
public final class DefaultSpissatusBuilder implements SpissatusBuilder {

    private static final System.Logger LOG = System.getLogger(DefaultSpissatusBuilder.class.getName());
    private static final String TRUSTED_PREFIX = ServiceModuleLoader.TRUSTED_PREFIX;

    private final Map<String, String> settings = new LinkedHashMap<>();
    private final List<AlgorithmProvider> explicitProviders = new ArrayList<>();
    private final List<AuditSink> explicitAuditSinks = new ArrayList<>();
    private final List<AlertSink> explicitAlertSinks = new ArrayList<>();
    private final Set<String> trustedModules = new HashSet<>();
    private final List<String> buildWarnings = new ArrayList<>();

    private ExtensionRegistry explicitRegistry;
    private KeyManager explicitKeyManager;
    private EnvelopeService explicitEnvelopeService;
    private StreamCipherService explicitStreamCipherService;
    private RandomService explicitRandomService;
    private PolicyEngine explicitPolicyEngine;
    private AuditTrail explicitAuditTrail;
    private MetricsRecorder explicitMetricsRecorder;
    private NonceReuseDetector explicitNonceDetector;
    private ComplianceMode complianceMode = ComplianceMode.STANDARD;
    private boolean complianceExplicit;
    private boolean failClosed = true;
    private boolean selfCheckOnStartup = true;
    private boolean selfCheckFailureFailsStartup = true;
    private boolean auditFailureFailsOperation;
    private boolean discoverModules = true;
    private Clock clock = Clock.systemUTC();

    @Override
    public SpissatusBuilder setting(String key, String value) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(value, "value");
        settings.put(key, value);
        return this;
    }

    @Override
    public SpissatusBuilder extensionRegistry(ExtensionRegistry registry) {
        this.explicitRegistry = registry;
        return this;
    }

    @Override
    public SpissatusBuilder algorithmProvider(AlgorithmProvider provider) {
        explicitProviders.add(Objects.requireNonNull(provider, "provider"));
        return this;
    }

    @Override
    public SpissatusBuilder keyManager(KeyManager manager) {
        this.explicitKeyManager = Objects.requireNonNull(manager, "manager");
        return this;
    }

    @Override
    public SpissatusBuilder envelopeService(EnvelopeService service) {
        this.explicitEnvelopeService = Objects.requireNonNull(service, "service");
        return this;
    }

    @Override
    public SpissatusBuilder streamCipherService(StreamCipherService service) {
        this.explicitStreamCipherService = Objects.requireNonNull(service, "service");
        return this;
    }

    @Override
    public SpissatusBuilder randomService(RandomService service) {
        this.explicitRandomService = Objects.requireNonNull(service, "service");
        return this;
    }

    @Override
    public SpissatusBuilder policyEngine(PolicyEngine engine) {
        this.explicitPolicyEngine = Objects.requireNonNull(engine, "engine");
        return this;
    }

    @Override
    public SpissatusBuilder auditTrail(AuditTrail trail) {
        this.explicitAuditTrail = Objects.requireNonNull(trail, "trail");
        return this;
    }

    @Override
    public SpissatusBuilder auditSink(AuditSink sink) {
        explicitAuditSinks.add(Objects.requireNonNull(sink, "sink"));
        return this;
    }

    @Override
    public SpissatusBuilder alertSink(AlertSink sink) {
        explicitAlertSinks.add(Objects.requireNonNull(sink, "sink"));
        return this;
    }

    @Override
    public SpissatusBuilder metricsRecorder(MetricsRecorder recorder) {
        this.explicitMetricsRecorder = Objects.requireNonNull(recorder, "recorder");
        return this;
    }

    @Override
    public SpissatusBuilder nonceReuseDetector(NonceReuseDetector detector) {
        this.explicitNonceDetector = Objects.requireNonNull(detector, "detector");
        return this;
    }

    @Override
    public SpissatusBuilder complianceMode(ComplianceMode mode) {
        this.complianceMode = Objects.requireNonNull(mode, "mode");
        this.complianceExplicit = true;
        return this;
    }

    @Override
    public SpissatusBuilder failClosed(boolean enabled) {
        this.failClosed = enabled;
        return this;
    }

    @Override
    public SpissatusBuilder selfCheckOnStartup(boolean enabled) {
        this.selfCheckOnStartup = enabled;
        return this;
    }

    @Override
    public SpissatusBuilder selfCheckFailureFailsStartup(boolean enabled) {
        this.selfCheckFailureFailsStartup = enabled;
        return this;
    }

    @Override
    public SpissatusBuilder auditFailureFailsOperation(boolean enabled) {
        this.auditFailureFailsOperation = enabled;
        return this;
    }

    @Override
    public SpissatusBuilder discoverModules(boolean enabled) {
        this.discoverModules = enabled;
        return this;
    }

    @Override
    public SpissatusBuilder trustModule(String moduleId) {
        trustedModules.add(Objects.requireNonNull(moduleId, "moduleId"));
        return this;
    }

    @Override
    public SpissatusBuilder clock(Clock value) {
        this.clock = Objects.requireNonNull(value, "clock");
        return this;
    }

    @Override
    public Spissatus build() {
        Clock buildClock = clock;
        ExtensionRegistry registry = explicitRegistry == null
                ? new DefaultExtensionRegistry() : explicitRegistry;
        ModuleContributions contributions = new ModuleContributions();
        contributions.settings.putAll(settings);
        if (complianceExplicit) {
            contributions.settings.put("spissatus.compliance.mode", complianceMode.name());
        }
        contributions.extensionRegistry = registry;
        DefaultModuleContext moduleContext = new DefaultModuleContext(contributions);

        List<SpissatusModule> modules = new ArrayList<>();
        if (discoverModules) {
            ServiceModuleLoader.Result discovered = ServiceModuleLoader.discover(trustedModules);
            modules.addAll(discovered.modules());
            contributions.rejectedModules.addAll(discovered.rejectedModuleIds());
            for (String rejected : discovered.rejectedModuleIds()) {
                LOG.log(System.Logger.Level.WARNING,
                        "Rejected untrusted spissatus4j module: {0}", rejected);
            }
            for (SpissatusModule module : modules) {
                try {
                    module.contribute(moduleContext);
                } catch (SpissatusException e) {
                    throw e;
                } catch (RuntimeException e) {
                    throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                            "Module contribution failed: " + module.moduleId(), e);
                }
            }
        }
        contributions.modules.addAll(modules);

        ComplianceMode effectiveMode = complianceExplicit
                ? complianceMode
                : parseComplianceMode(settings.get("spissatus.compliance.mode"));
        boolean fipsSetting = Boolean.parseBoolean(
                settings.getOrDefault("spissatus.fips.enabled", "false"));
        if (fipsSetting) {
            if (effectiveMode != ComplianceMode.STANDARD
                    && effectiveMode != ComplianceMode.FIPS) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "FIPS cannot be combined with compliance mode " + effectiveMode);
            }
            effectiveMode = ComplianceMode.FIPS;
        }

        // Explicit providers override discovered providers with the same id.
        for (AlgorithmProvider provider : explicitProviders) {
            AlgorithmProvider previous = contributions.algorithmProviders.put(
                    provider.providerId(), provider);
            if (previous != null && previous != provider) {
                buildWarnings.add("Explicit provider overrides module provider "
                        + provider.providerId());
            }
        }

        List<AlgorithmProvider> providers = new ArrayList<>(contributions.algorithmProviders.values());
        providers.sort(Comparator.comparingInt(AlgorithmProvider::priority).reversed()
                .thenComparing(AlgorithmProvider::providerId));
        KeyManager keyManager = null;
        AuditTrail auditTrail = null;
        try {
        if (providers.isEmpty()) {
            throw new ConfigurationException(ErrorCode.MISSING_DEPENDENCY,
                    "At least one AlgorithmProvider is required");
        }

        PolicyEngine basePolicy = explicitPolicyEngine != null ? explicitPolicyEngine
                : contributions.policyEngine != null ? contributions.policyEngine
                : new StrictPolicyEngine(effectiveMode, buildClock);
        PolicyEngine policyEngine = contributions.policyProviders.isEmpty()
                ? basePolicy
                : new ContributorPolicyEngine(basePolicy, contributions.policyProviders);

        List<AuditSink> auditSinks = mergeSinks(contributions.auditSinks, explicitAuditSinks);
        auditTrail = explicitAuditTrail;
        AuditTrail moduleTrail = registry.find(AuditTrail.class, "default")
                .orElseGet(() -> registry.all(AuditTrail.class).stream().findFirst().orElse(null));
        if (auditTrail == null && moduleTrail != null) {
            if (!explicitAuditSinks.isEmpty()) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Explicit audit sinks cannot be combined with a module-managed audit trail; "
                                + "configure sinks through the audit module settings");
            }
            auditTrail = moduleTrail;
        }
        if (auditTrail == null) {
            auditTrail = newDefaultTrail(auditSinks, buildClock);
        }

        MetricsRecorder metrics = explicitMetricsRecorder != null ? explicitMetricsRecorder
                : contributions.metricsRecorder != null ? contributions.metricsRecorder
                : new DefaultMetricsRecorder();
        RandomService random = explicitRandomService != null ? explicitRandomService
                : contributions.randomService != null ? contributions.randomService
                : new SystemRandomService();
        NonceReuseDetector nonceDetector = explicitNonceDetector != null ? explicitNonceDetector
                : new BoundedNonceReuseDetector(
                intSetting("spissatus.nonce.max-entries", 1_000_000, 1, 100_000_000),
                Duration.ofHours(intSetting("spissatus.nonce.ttl-hours", 24, 1, 24 * 365)),
                buildClock);

        keyManager = explicitKeyManager;
        if (keyManager == null) {
            KeyManagerFactory factory = contributions.keyManagerFactories.get("default-key-manager");
            if (factory == null && !contributions.keyManagerFactories.isEmpty()) {
                factory = contributions.keyManagerFactories.values().stream()
                        .sorted(Comparator.comparing(KeyManagerFactory::factoryId))
                        .findFirst().orElse(null);
            }
            if (factory == null) {
                throw new ConfigurationException(ErrorCode.MISSING_DEPENDENCY,
                        "No KeyManager or KeyManagerFactory is available");
            }
            List<KeyWrapper> wrappers = List.copyOf(contributions.keyWrappers);
            KeyManagerDependencies dependencies = new KeyManagerDependencies(policyEngine,
                    auditTrail, buildClock, wrappers, List.copyOf(contributions.keyProviders.values()),
                    settings);
            try {
                keyManager = factory.create(dependencies);
            } catch (SpissatusException e) {
                throw e;
            } catch (RuntimeException e) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Key manager creation failed", e);
            }
            if (keyManager == null) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Key manager factory returned null");
            }
        }

        EnvelopeService envelopeService = explicitEnvelopeService != null ? explicitEnvelopeService
                : contributions.envelopeService;
        StreamCipherService streamService = explicitStreamCipherService != null
                ? explicitStreamCipherService : contributions.streamCipherService;

        List<AlertSink> alertSinks = new ArrayList<>(contributions.alertSinks);
        alertSinks.addAll(explicitAlertSinks);
        if (alertSinks.isEmpty()) {
            alertSinks.add(new LoggingAlertSink());
        }

        DefaultFailClosedGuard guard = new DefaultFailClosedGuard(RuntimeState.STARTING);
        Map<String, HealthStatus> providerHealth = new LinkedHashMap<>();

        boolean fipsRequested = effectiveMode == ComplianceMode.FIPS;
        boolean fipsActive = "true".equalsIgnoreCase(
                contributions.attributes.getOrDefault("spissatus.fips.active", "false"))
                || providers.stream().anyMatch(AlgorithmProvider::fipsCapable);
        if (fipsRequested && !fipsActive) {
            throw new ConfigurationException(ErrorCode.SELF_CHECK_FAILED,
                    "FIPS mode requested but no FIPS provider is active");
        }

        SelfCheckReport report;
        if (selfCheckOnStartup) {
            Instant started = buildClock.instant();
            List<SelfCheckResult> checks = new ArrayList<>();
            for (AlgorithmProvider provider : providers) {
                HealthStatus status;
                try {
                    SelfCheckReport providerReport = provider.selfCheck();
                    status = providerReport.overall();
                    for (SelfCheckResult result : providerReport.checks()) {
                        checks.add(prefix("provider." + provider.providerId(), result));
                    }
                } catch (RuntimeException e) {
                    status = HealthStatus.DOWN;
                    checks.add(SelfCheckResult.down("provider." + provider.providerId() + ".selfcheck",
                            "Provider self-check failed"));
                }
                providerHealth.put(provider.providerId(), status);
            }
            checks.add(healthCheck("policy", policyEngine::health));
            boolean auditProbeFailed = false;
            try {
                auditTrail.append(AuditEvent.builder(AuditEventType.SELF_CHECK,
                                AuditSeverity.INFO, AuditOutcome.SUCCESS)
                        .callerId("system").tenantId("system")
                        .message("Startup audit probe").build());
            } catch (RuntimeException e) {
                auditProbeFailed = true;
            }
            HealthStatus auditHealth = auditProbeFailed ? HealthStatus.DOWN
                    : healthOf(auditTrail::health);
            HealthStatus auditCheck = auditHealth == HealthStatus.UP
                    ? HealthStatus.UP : HealthStatus.DOWN;
            checks.add(new SelfCheckResult("audit", auditCheck,
                    auditCheck == HealthStatus.UP ? "Audit trail healthy" : "Audit trail unavailable",
                    Duration.ZERO));
            try {
                var chain = auditTrail.verify();
                checks.add(chain.intact()
                        ? SelfCheckResult.up("audit.chain", "Audit chain intact")
                        : SelfCheckResult.down("audit.chain", "Audit chain verification failed"));
            } catch (RuntimeException e) {
                checks.add(SelfCheckResult.down("audit.chain", "Audit chain verification failed"));
            }
            checks.add(healthCheck("random", random::health));
            checks.add(healthCheck("nonce-detector", nonceDetector::health));
            checks.add(healthCheck("key-manager", keyManager::health));
            for (SpissatusModule module : modules) {
                try {
                    SelfCheckReport moduleReport = module.selfCheck();
                    for (SelfCheckResult result : moduleReport.checks()) {
                        checks.add(prefix("module." + module.moduleId(), result));
                    }
                } catch (RuntimeException e) {
                    checks.add(SelfCheckResult.down("module." + module.moduleId() + ".selfcheck",
                            "Module self-check failed"));
                }
            }
            boolean gmAvailable = providers.stream().flatMap(p -> safeAlgorithms(p).stream())
                    .anyMatch(a -> a.id().startsWith("SM2") || a.id().startsWith("SM3")
                            || a.id().startsWith("SM4"));
            if (effectiveMode == ComplianceMode.GM && !gmAvailable) {
                checks.add(SelfCheckResult.down("compliance.gm",
                        "GM compliance requested but no SM algorithm is available"));
            }
            Instant completed = buildClock.instant();
            report = new SelfCheckReport(started, completed, checks);
            HealthStatus overall = report.overall();
            if (overall == HealthStatus.DOWN) {
                if (failClosed) {
                    if (selfCheckFailureFailsStartup) {
                        String failed = report.failures().stream().map(SelfCheckResult::checkId)
                                .reduce((a, b) -> a + "," + b).orElse("unknown");
                        throw new ConfigurationException(ErrorCode.SELF_CHECK_FAILED,
                                "Startup self-check failed: " + failed);
                    }
                    guard.transitionTo(RuntimeState.UNAVAILABLE);
                } else {
                    guard.transitionTo(RuntimeState.DEGRADED);
                }
            } else if (overall == HealthStatus.DEGRADED) {
                guard.transitionTo(RuntimeState.DEGRADED);
            } else {
                guard.transitionTo(RuntimeState.READY);
            }
        } else {
            for (AlgorithmProvider provider : providers) {
                providerHealth.put(provider.providerId(), HealthStatus.UP);
            }
            Instant now = buildClock.instant();
            report = new SelfCheckReport(now, now, List.of());
            guard.transitionTo(RuntimeState.READY);
        }

        recordBuildAudit(auditTrail, modules, contributions.rejectedModules, providers,
                effectiveMode, report);

        boolean effectiveAuditFailureFails = auditFailureFailsOperation
                || Boolean.parseBoolean(settings.getOrDefault(
                        "spissatus.audit.fail-on-sink-failure", "false"));
        FacadeContext context = new FacadeContext(providers, policyEngine, keyManager, auditTrail,
                guard, random, nonceDetector, new DefaultConstantTimeComparator(),
                new DefaultSensitiveDataRedactor(), metrics, List.copyOf(alertSinks),
                effectiveMode, buildClock, failClosed, effectiveAuditFailureFails,
                envelopeService, streamService, report, Map.copyOf(providerHealth),
                List.copyOf(modules), registry, Map.copyOf(settings));

        DefaultSpissatus facade = new DefaultSpissatus(context, guard);
        for (String warning : buildWarnings) {
            LOG.log(System.Logger.Level.WARNING, warning);
        }
        return facade;
        } catch (RuntimeException e) {
            closeBuildResources(providers, keyManager, auditTrail, modules);
            throw e;
        }
    }

    private AuditTrail newDefaultTrail(List<AuditSink> sinks, Clock buildClock) {
        int maxRetained = intSetting("spissatus.audit.buffer-size", 10_000, 1, 10_000_000);
        List<AuditSink> effective = new ArrayList<>(sinks);
        if (effective.isEmpty()) {
            effective.add(new InMemoryAuditSink(maxRetained));
        }
        SecretKey key = auditHmacKey();
        return new HmacChainedAuditTrail(effective, key, maxRetained);
    }

    private SecretKey auditHmacKey() {
        String configured = settings.get("spissatus.audit.hmac-key");
        if (configured != null && !configured.isBlank()) {
            try {
                byte[] decoded = Base64.getDecoder().decode(configured.trim());
                if (decoded.length < 32) {
                    throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                            "Audit HMAC key must contain at least 32 bytes");
                }
                return new SecretKeySpec(decoded, "HmacSHA256");
            } catch (IllegalArgumentException e) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Audit HMAC key is not valid Base64");
            }
        }
        try {
            KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
            generator.init(256);
            return generator.generateKey();
        } catch (Exception e) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Unable to generate an ephemeral audit HMAC key", e);
        }
    }

    private void recordBuildAudit(AuditTrail trail, List<SpissatusModule> modules,
                                  List<String> rejected, List<AlgorithmProvider> providers,
                                  ComplianceMode mode, SelfCheckReport report) {
        for (SpissatusModule module : modules) {
            safeAudit(trail, AuditEvent.builder(AuditEventType.MODULE_REGISTERED,
                            AuditSeverity.INFO, AuditOutcome.SUCCESS)
                    .callerId("system").tenantId("system")
                    .message("Module registered")
                    .detail("moduleId", module.moduleId()));
        }
        for (String moduleId : rejected) {
            safeAudit(trail, AuditEvent.builder(AuditEventType.MODULE_REJECTED,
                            AuditSeverity.WARN, AuditOutcome.DENIED)
                    .callerId("system").tenantId("system")
                    .message("Untrusted module rejected")
                    .detail("moduleId", moduleId));
        }
        for (AlgorithmProvider provider : providers) {
            safeAudit(trail, AuditEvent.builder(AuditEventType.PROVIDER_REGISTERED,
                            AuditSeverity.INFO, AuditOutcome.SUCCESS)
                    .callerId("system").tenantId("system")
                    .message("Algorithm provider registered")
                    .detail("providerId", provider.providerId()));
        }
        safeAudit(trail, AuditEvent.builder(AuditEventType.SELF_CHECK,
                        report.overall() == HealthStatus.DOWN ? AuditSeverity.ERROR : AuditSeverity.INFO,
                        report.overall() == HealthStatus.DOWN ? AuditOutcome.FAILURE : AuditOutcome.SUCCESS)
                .callerId("system").tenantId("system")
                .message("Startup self-check completed")
                .detail("overall", report.overall().name()));
        safeAudit(trail, AuditEvent.builder(AuditEventType.CONFIG_CHANGED,
                        AuditSeverity.INFO, AuditOutcome.SUCCESS)
                .callerId("system").tenantId("system")
                .message("Facade assembled")
                .detail("complianceMode", mode.name())
                .detail("failClosed", Boolean.toString(failClosed)));
    }

    private static void safeAudit(AuditTrail trail, AuditEvent.Builder builder) {
        try {
            trail.append(builder.build());
        } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.WARNING, "Build audit event could not be recorded");
        }
    }

    private List<AuditSink> mergeSinks(List<AuditSink> contributed, List<AuditSink> explicit) {
        Map<String, AuditSink> byId = new LinkedHashMap<>();
        for (AuditSink sink : contributed) {
            byId.put(sink.sinkId(), sink);
        }
        for (AuditSink sink : explicit) {
            AuditSink previous = byId.put(sink.sinkId(), sink);
            if (previous != null && previous != sink) {
                buildWarnings.add("Explicit audit sink overrides module sink " + sink.sinkId());
            }
        }
        return List.copyOf(byId.values());
    }

    private static Set<cn.tolim.spissatus4j.contract.algorithm.AlgorithmId> safeAlgorithms(
            AlgorithmProvider provider) {
        try {
            return Set.copyOf(provider.supportedAlgorithms());
        } catch (RuntimeException e) {
            return Set.of();
        }
    }

    private static HealthStatus healthOf(java.util.function.Supplier<HealthStatus> supplier) {
        try {
            HealthStatus status = supplier.get();
            return status == null ? HealthStatus.DOWN : status;
        } catch (RuntimeException e) {
            return HealthStatus.DOWN;
        }
    }

    private static void closeBuildResources(List<AlgorithmProvider> providers, KeyManager keyManager,
                                            AuditTrail auditTrail, List<SpissatusModule> modules) {
        for (SpissatusModule module : modules) {
            try {
                module.close();
            } catch (RuntimeException ignored) {
                // best effort cleanup
            }
        }
        if (auditTrail != null) {
            try {
                auditTrail.close();
            } catch (RuntimeException ignored) {
            }
        }
        if (keyManager != null) {
            try {
                keyManager.close();
            } catch (RuntimeException ignored) {
            }
        }
        for (AlgorithmProvider provider : providers) {
            try {
                provider.close();
            } catch (RuntimeException ignored) {
            }
        }
    }

    private static SelfCheckResult healthCheck(String id,
                                               java.util.function.Supplier<HealthStatus> supplier) {
        try {
            HealthStatus status = supplier.get();
            return new SelfCheckResult(id, status, "Health status " + status, Duration.ZERO);
        } catch (RuntimeException e) {
            return SelfCheckResult.down(id, "Health check failed");
        }
    }

    private static SelfCheckResult prefix(String prefix, SelfCheckResult result) {
        return new SelfCheckResult(prefix + "." + result.checkId(), result.status(),
                result.message(), result.duration());
    }

    private int intSetting(String key, int defaultValue, int min, int max) {
        String value = settings.get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < min || parsed > max) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Configuration value out of range: " + key);
            }
            return parsed;
        } catch (NumberFormatException e) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Configuration value is not an integer: " + key);
        }
    }

    private static ComplianceMode parseComplianceMode(String value) {
        if (value == null || value.isBlank()) {
            return ComplianceMode.STANDARD;
        }
        String normalized = value.trim().toUpperCase().replace('-', '_');
        try {
            return ComplianceMode.valueOf(normalized);
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Unsupported compliance mode: " + value);
        }
    }
}