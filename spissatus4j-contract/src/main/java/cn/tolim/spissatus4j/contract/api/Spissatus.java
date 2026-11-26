package cn.tolim.spissatus4j.contract.api;

import cn.tolim.spissatus4j.contract.audit.AuditTrail;
import cn.tolim.spissatus4j.contract.audit.MetricsRecorder;
import cn.tolim.spissatus4j.contract.crypto.EncryptRequest;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.key.KeyManager;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.RuntimeState;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;

/**
 * Main entry point. Instances are long-lived, thread-safe and must be closed.
 */
public interface Spissatus extends AutoCloseable {

    CryptoService crypto();

    KeyManager keyManager();

    EnvelopeService envelopeService();

    StreamCipherService streamCipherService();

    PolicyEngine policyEngine();

    AuditTrail auditTrail();

    /** Bounded, non-sensitive operational metrics for management endpoints. */
    MetricsRecorder metricsRecorder();

    Capabilities capabilities();

    SelfCheckReport selfCheckReport();

    HealthStatus health();

    RuntimeState state();

    /** Encrypts and wraps the result in a self-describing envelope. */
    Envelope encryptToEnvelope(EncryptRequest request, EnvelopeFormat format, BinaryEncoding encoding);

    /** Decodes an envelope, validates it, decrypts it and audits the operation. */
    byte[] decryptEnvelope(byte[] encodedEnvelope, CallerContext caller);

    @Override
    void close();
}