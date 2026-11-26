package cn.tolim.spissatus4j.contract.api;

import cn.tolim.spissatus4j.contract.audit.AuditTrail;
import cn.tolim.spissatus4j.contract.audit.MetricsRecorder;
import cn.tolim.spissatus4j.contract.crypto.EncryptRequest;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.envelope.BinaryEncoding;
import cn.tolim.spissatus4j.contract.envelope.Envelope;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeFormat;
import cn.tolim.spissatus4j.contract.envelope.EnvelopeService;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyManager;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.RuntimeState;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.unified.SelectionCapabilities;
import cn.tolim.spissatus4j.contract.unified.UnifiedDecryptRequest;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptRequest;
import cn.tolim.spissatus4j.contract.unified.UnifiedEncryptionResult;

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

    /**
     * Unified encryption entry point. Selects one primary algorithm from the
     * installed, compliant, authorized and key-compatible capabilities,
     * performs exactly one policy decision and returns a v2 envelope whose
     * metadata is authenticated. This is capability aggregation, not
     * multi-algorithm repeated encryption.
     */
    default UnifiedEncryptionResult encrypt(UnifiedEncryptRequest request) {
        throw new ConfigurationException(ErrorCode.UNSUPPORTED_OPERATION,
                "Unified encryption is not supported by this implementation");
    }

    /**
     * Unified decryption entry point. Verifies v2 envelope metadata binding
     * before routing to the low-level decrypt operation. Legacy v1 envelopes
     * are rejected unless explicitly allowed.
     */
    default byte[] decrypt(UnifiedDecryptRequest request) {
        throw new ConfigurationException(ErrorCode.UNSUPPORTED_OPERATION,
                "Unified decryption is not supported by this implementation");
    }

    /** Read-only capability view used to explain unified algorithm selection. */
    default SelectionCapabilities selectionCapabilities() {
        return SelectionCapabilities.from(capabilities());
    }

    @Override
    void close();
}