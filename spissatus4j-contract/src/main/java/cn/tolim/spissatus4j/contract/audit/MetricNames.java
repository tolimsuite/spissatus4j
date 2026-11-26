package cn.tolim.spissatus4j.contract.audit;

/** Stable metric names. */
public final class MetricNames {

    public static final String OPERATIONS = "spissatus.operations";
    public static final String OPERATION_LATENCY = "spissatus.operation.latency";
    public static final String POLICY_DENIALS = "spissatus.policy.denials";
    public static final String POLICY_WARNINGS = "spissatus.policy.warnings";
    public static final String SELF_CHECK_STATUS = "spissatus.selfcheck.status";
    public static final String KEY_STATE_COUNT = "spissatus.keys.state";
    public static final String NONCE_REUSE = "spissatus.nonce.reuse";
    public static final String AUDIT_WRITE_FAILURES = "spissatus.audit.write.failures";
    public static final String AUDIT_EVENTS = "spissatus.audit.events";
    public static final String STREAM_BYTES = "spissatus.stream.bytes";
    public static final String STREAM_FAILURES = "spissatus.stream.failures";
    public static final String ALGORITHM_SELECTIONS = "spissatus.selection.operations";
    public static final String ALGORITHM_SELECTION_FAILURES = "spissatus.selection.rejections";
    public static final String ENVELOPE_BINDING_FAILURES = "spissatus.envelope.binding.failures";

    private MetricNames() {
    }
}