package cn.tolim.spissatus4j.core.facade;

import cn.tolim.spissatus4j.contract.audit.AlertSink;
import cn.tolim.spissatus4j.contract.audit.AuditTrail;
import cn.tolim.spissatus4j.contract.audit.MetricsRecorder;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.crypto.RandomService;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.key.KeyManager;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.runtime.ConstantTimeComparator;
import cn.tolim.spissatus4j.contract.runtime.FailClosedGuard;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.NonceReuseDetector;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.runtime.SensitiveDataRedactor;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.contract.spi.ExtensionRegistry;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Immutable dependency bundle for the facade and crypto service. */
public record FacadeContext(
        List<AlgorithmProvider> providers,
        PolicyEngine policyEngine,
        KeyManager keyManager,
        AuditTrail auditTrail,
        FailClosedGuard guard,
        RandomService randomService,
        NonceReuseDetector nonceReuseDetector,
        ConstantTimeComparator constantTimeComparator,
        SensitiveDataRedactor redactor,
        MetricsRecorder metricsRecorder,
        List<AlertSink> alertSinks,
        ComplianceMode complianceMode,
        Clock clock,
        boolean failClosed,
        boolean auditFailureFailsOperation,
        EnvelopeService envelopeService,
        StreamCipherService streamCipherService,
        SelfCheckReport selfCheckReport,
        Map<String, HealthStatus> providerHealth,
        List<SpissatusModule> modules,
        ExtensionRegistry extensionRegistry,
        Map<String, String> settings) {

    public FacadeContext {
        providers = List.copyOf(Objects.requireNonNull(providers, "providers"));
        Objects.requireNonNull(policyEngine, "policyEngine");
        Objects.requireNonNull(keyManager, "keyManager");
        Objects.requireNonNull(auditTrail, "auditTrail");
        Objects.requireNonNull(guard, "guard");
        Objects.requireNonNull(randomService, "randomService");
        Objects.requireNonNull(nonceReuseDetector, "nonceReuseDetector");
        Objects.requireNonNull(constantTimeComparator, "constantTimeComparator");
        Objects.requireNonNull(redactor, "redactor");
        Objects.requireNonNull(metricsRecorder, "metricsRecorder");
        alertSinks = List.copyOf(Objects.requireNonNull(alertSinks, "alertSinks"));
        Objects.requireNonNull(complianceMode, "complianceMode");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(selfCheckReport, "selfCheckReport");
        providerHealth = Map.copyOf(Objects.requireNonNull(providerHealth, "providerHealth"));
        modules = List.copyOf(Objects.requireNonNull(modules, "modules"));
        Objects.requireNonNull(extensionRegistry, "extensionRegistry");
        settings = Map.copyOf(Objects.requireNonNull(settings, "settings"));
    }

    @Override
    public String toString() {
        return "FacadeContext[providers=" + providers.size()
                + ", complianceMode=" + complianceMode
                + ", failClosed=" + failClosed
                + ", auditFailureFailsOperation=" + auditFailureFailsOperation
                + ", settings=redacted]";
    }
}