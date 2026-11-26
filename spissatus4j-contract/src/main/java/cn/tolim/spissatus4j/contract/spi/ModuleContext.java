package cn.tolim.spissatus4j.contract.spi;

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
import java.util.Map;
import java.util.Optional;

/** Registration surface exposed to discovered modules during facade assembly. */
public interface ModuleContext {

    void registerAlgorithmProvider(AlgorithmProvider provider);

    void registerKeyProvider(KeyProvider provider);

    void registerKeyManagerFactory(KeyManagerFactory factory);

    void registerEnvelopeCodec(EnvelopeCodec codec);

    void registerEnvelopeService(EnvelopeService service);

    void registerStreamCipherService(StreamCipherService service);

    void registerRandomService(RandomService service);

    void registerPolicyEngine(PolicyEngine engine);

    void registerPolicyProvider(PolicyProvider provider);

    void registerAuditSink(AuditSink sink);

    void registerMetricsRecorder(MetricsRecorder recorder);

    void registerAlertSink(AlertSink sink);

    void registerKeyWrapper(KeyWrapper wrapper);

    /** Generic extension registration for third-party contracts. */
    void register(Class<?> type, String id, Object extension);

    Optional<String> setting(String key);

    /** Raw settings may contain secrets; never log this map or its values. */
    Map<String, String> settings();

    void attribute(String key, String value);
}