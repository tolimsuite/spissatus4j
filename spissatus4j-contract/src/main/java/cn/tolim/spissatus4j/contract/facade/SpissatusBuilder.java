package cn.tolim.spissatus4j.contract.facade;

import cn.tolim.spissatus4j.contract.audit.AlertSink;
import cn.tolim.spissatus4j.contract.audit.AuditSink;
import cn.tolim.spissatus4j.contract.audit.AuditTrail;
import cn.tolim.spissatus4j.contract.audit.MetricsRecorder;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.crypto.RandomService;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.key.KeyManager;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.runtime.NonceReuseDetector;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import cn.tolim.spissatus4j.contract.spi.ExtensionRegistry;
import java.time.Clock;

/**
 * Explicit assembly contract. Modules are discovered from the classpath and
 * can be overridden here; at least one algorithm provider and a key manager
 * are required (the key module contributes a default factory).
 *
 * <p>Fail-closed behaviour is enabled by default: a failed startup self-check
 * prevents the facade from being built.</p>
 */
public interface SpissatusBuilder {

    SpissatusBuilder setting(String key, String value);

    SpissatusBuilder extensionRegistry(ExtensionRegistry registry);

    SpissatusBuilder algorithmProvider(AlgorithmProvider provider);

    SpissatusBuilder keyManager(KeyManager manager);

    SpissatusBuilder envelopeService(EnvelopeService service);

    SpissatusBuilder streamCipherService(StreamCipherService service);

    SpissatusBuilder randomService(RandomService service);

    SpissatusBuilder policyEngine(PolicyEngine engine);

    SpissatusBuilder auditTrail(AuditTrail trail);

    SpissatusBuilder auditSink(AuditSink sink);

    SpissatusBuilder alertSink(AlertSink sink);

    SpissatusBuilder metricsRecorder(MetricsRecorder recorder);

    SpissatusBuilder nonceReuseDetector(NonceReuseDetector detector);

    SpissatusBuilder complianceMode(ComplianceMode mode);

    SpissatusBuilder failClosed(boolean enabled);

    SpissatusBuilder selfCheckOnStartup(boolean enabled);

    SpissatusBuilder selfCheckFailureFailsStartup(boolean enabled);

    SpissatusBuilder auditFailureFailsOperation(boolean enabled);

    SpissatusBuilder discoverModules(boolean enabled);

    /**
     * Trusts a third-party module by its fully-qualified implementation class
     * name. Self-declared module ids are not sufficient for trust.
     */
    SpissatusBuilder trustModule(String moduleClassName);

    SpissatusBuilder clock(Clock clock);

    Spissatus build();
}