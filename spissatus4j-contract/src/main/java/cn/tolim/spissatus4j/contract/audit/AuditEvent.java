package cn.tolim.spissatus4j.contract.audit;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Immutable audit record. Chain fields {@code sequence}, {@code previousHash}
 * and {@code hash} are filled by the audit trail.
 *
 * <p>Messages and details must be non-sensitive. Never place plaintext, key
 * material, passwords or complete ciphertext in an audit event.</p>
 */
public final class AuditEvent {

    private final UUID eventId;
    private final Instant timestamp;
    private final AuditEventType type;
    private final AuditSeverity severity;
    private final AuditOutcome outcome;
    private final String callerId;
    private final String tenantId;
    private final AlgorithmId algorithm;
    private final KeyId keyId;
    private final KeyVersion keyVersion;
    private final Operation operation;
    private final String message;
    private final Map<String, String> details;
    private final long sequence;
    private final String previousHash;
    private final String hash;

    private AuditEvent(Builder builder) {
        this.eventId = Objects.requireNonNull(builder.eventId, "eventId");
        this.timestamp = Objects.requireNonNull(builder.timestamp, "timestamp");
        this.type = Objects.requireNonNull(builder.type, "type");
        this.severity = Objects.requireNonNull(builder.severity, "severity");
        this.outcome = Objects.requireNonNull(builder.outcome, "outcome");
        this.callerId = builder.caller == null ? builder.callerId : builder.caller.callerId();
        this.tenantId = builder.caller == null ? builder.tenantId : builder.caller.tenantId();
        this.algorithm = builder.algorithm;
        this.keyId = builder.keyId;
        this.keyVersion = builder.keyVersion;
        this.operation = builder.operation;
        this.message = builder.message == null ? "" : builder.message;
        this.details = Map.copyOf(Objects.requireNonNull(builder.details, "details"));
        this.sequence = builder.sequence;
        this.previousHash = builder.previousHash;
        this.hash = builder.hash;
    }

    public static Builder builder(AuditEventType type, AuditSeverity severity, AuditOutcome outcome) {
        return new Builder().type(type).severity(severity).outcome(outcome);
    }

    public static Builder builder(AuditEventType type) {
        return new Builder().type(type);
    }

    public UUID eventId() {
        return eventId;
    }

    public Instant timestamp() {
        return timestamp;
    }

    public AuditEventType type() {
        return type;
    }

    public AuditSeverity severity() {
        return severity;
    }

    public AuditOutcome outcome() {
        return outcome;
    }

    public String callerId() {
        return callerId;
    }

    public String tenantId() {
        return tenantId;
    }

    public AlgorithmId algorithm() {
        return algorithm;
    }

    public KeyId keyId() {
        return keyId;
    }

    public KeyVersion keyVersion() {
        return keyVersion;
    }

    public Operation operation() {
        return operation;
    }

    public String message() {
        return message;
    }

    public Map<String, String> details() {
        return details;
    }

    public long sequence() {
        return sequence;
    }

    public String previousHash() {
        return previousHash;
    }

    public String hash() {
        return hash;
    }

    public AuditEvent withChain(long newSequence, String newPreviousHash, String newHash) {
        Builder builder = toBuilder();
        builder.sequence = newSequence;
        builder.previousHash = newPreviousHash;
        builder.hash = newHash;
        return new AuditEvent(builder);
    }

    public Builder toBuilder() {
        Builder builder = new Builder();
        builder.eventId = eventId;
        builder.timestamp = timestamp;
        builder.type = type;
        builder.severity = severity;
        builder.outcome = outcome;
        builder.callerId = callerId;
        builder.tenantId = tenantId;
        builder.algorithm = algorithm;
        builder.keyId = keyId;
        builder.keyVersion = keyVersion;
        builder.operation = operation;
        builder.message = message;
        builder.details = details;
        builder.sequence = sequence;
        builder.previousHash = previousHash;
        builder.hash = hash;
        return builder;
    }

    @Override
    public String toString() {
        return "AuditEvent[sequence=" + sequence + ", type=" + type + ", severity=" + severity
                + ", outcome=" + outcome + ", callerId=" + callerId + ", keyId=" + keyId + "]";
    }

    public static final class Builder {
        private UUID eventId = UUID.randomUUID();
        private Instant timestamp = Instant.now();
        private AuditEventType type;
        private AuditSeverity severity = AuditSeverity.INFO;
        private AuditOutcome outcome = AuditOutcome.INFO;
        private CallerContext caller;
        private String callerId;
        private String tenantId;
        private AlgorithmId algorithm;
        private KeyId keyId;
        private KeyVersion keyVersion;
        private Operation operation;
        private String message;
        private Map<String, String> details = Map.of();
        private long sequence;
        private String previousHash;
        private String hash;

        public Builder eventId(UUID value) {
            this.eventId = value;
            return this;
        }

        public Builder timestamp(Instant value) {
            this.timestamp = value;
            return this;
        }

        public Builder type(AuditEventType value) {
            this.type = value;
            return this;
        }

        public Builder severity(AuditSeverity value) {
            this.severity = value;
            return this;
        }

        public Builder outcome(AuditOutcome value) {
            this.outcome = value;
            return this;
        }

        public Builder caller(CallerContext value) {
            this.caller = value;
            return this;
        }

        public Builder callerId(String value) {
            this.callerId = value;
            return this;
        }

        public Builder tenantId(String value) {
            this.tenantId = value;
            return this;
        }

        public Builder algorithm(AlgorithmId value) {
            this.algorithm = value;
            return this;
        }

        public Builder keyId(KeyId value) {
            this.keyId = value;
            return this;
        }

        public Builder keyVersion(KeyVersion value) {
            this.keyVersion = value;
            return this;
        }

        public Builder operation(Operation value) {
            this.operation = value;
            return this;
        }

        public Builder message(String value) {
            this.message = value;
            return this;
        }

        public Builder details(Map<String, String> value) {
            this.details = value;
            return this;
        }

        public Builder detail(String name, String value) {
            var mutable = new java.util.LinkedHashMap<>(details);
            mutable.put(name, value);
            this.details = Map.copyOf(mutable);
            return this;
        }

        public AuditEvent build() {
            if (type == null) {
                throw new IllegalStateException("Audit event type is required");
            }
            return new AuditEvent(this);
        }
    }
}