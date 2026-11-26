package cn.tolim.spissatus4j.core.audit;

import cn.tolim.spissatus4j.contract.audit.AuditChainStatus;
import cn.tolim.spissatus4j.contract.audit.AuditEvent;
import cn.tolim.spissatus4j.contract.audit.AuditSink;
import cn.tolim.spissatus4j.contract.audit.AuditTrail;
import cn.tolim.spissatus4j.contract.exception.AuditException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Default append-only, HMAC-chained audit trail.
 *
 * <p>The trail retains the most recent {@code maxRetained} chained events for
 * verification and exposes them through {@link #recent(int)}. Sink failures
 * degrade health but never drop the event or block other sinks.</p>
 */
public final class HmacChainedAuditTrail implements AuditTrail {

    private static final System.Logger LOG = System.getLogger(HmacChainedAuditTrail.class.getName());
    private static final String GENESIS = "GENESIS";

    private final List<AuditSink> sinks;
    private final SecretKey hmacKey;
    private final int maxRetained;
    private final Deque<AuditEvent> events = new ArrayDeque<>();
    private final java.util.Set<AuditSink> disabledSinks =
            java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
    private long sequence;
    private String lastHash = GENESIS;
    private boolean sinkFailure;
    private boolean closed;

    public HmacChainedAuditTrail(List<AuditSink> sinks, SecretKey hmacKey, int maxRetained) {
        this.sinks = List.copyOf(Objects.requireNonNull(sinks, "sinks"));
        Objects.requireNonNull(hmacKey, "hmacKey");
        byte[] encoded = hmacKey.getEncoded();
        if (encoded == null || encoded.length < 32) {
            throw new AuditException(ErrorCode.AUDIT_FAILURE,
                    "Audit HMAC key must contain at least 32 bytes");
        }
        this.hmacKey = new SecretKeySpec(encoded, "HmacSHA256");
        if (maxRetained < 1) {
            throw new IllegalArgumentException("maxRetained must be positive");
        }
        this.maxRetained = maxRetained;
    }

    @Override
    public synchronized AuditEvent append(AuditEvent event) {
        Objects.requireNonNull(event, "event");
        if (closed) {
            throw new AuditException(ErrorCode.AUDIT_FAILURE, "Audit trail is closed");
        }
        sequence++;
        String previousHash = lastHash;
        String hash = AuditHashing.hash(hmacKey, sequence, previousHash, event);
        AuditEvent chained = event.withChain(sequence, previousHash, hash);
        events.addLast(chained);
        while (events.size() > maxRetained) {
            events.removeFirst();
        }
        lastHash = hash;
        for (AuditSink sink : sinks) {
            if (disabledSinks.contains(sink)) {
                continue;
            }
            try {
                sink.write(chained);
                sink.flush();
            } catch (RuntimeException e) {
                // Do not retry a sink after a failed write: skipping the event and
                // then writing later events would create an unverifiable gap.
                disabledSinks.add(sink);
                sinkFailure = true;
                LOG.log(System.Logger.Level.WARNING,
                        "Audit sink failed and is disabled: {0}", sink.sinkId());
            }
        }
        return chained;
    }

    @Override
    public synchronized AuditChainStatus verify() {
        if (events.isEmpty()) {
            return sequence == 0
                    ? AuditChainStatus.intact(0, null)
                    : AuditChainStatus.broken(0, "Retained audit chain is empty");
        }
        boolean evicted = sequence > maxRetained;
        AuditEvent first = events.peekFirst();
        if (!evicted && (first.sequence() != 1 || !GENESIS.equals(first.previousHash()))) {
            return AuditChainStatus.broken(0, "Audit chain does not start at sequence 1");
        }
        AuditEvent previous = null;
        long verified = 0;
        long expectedSequence = first.sequence();
        for (AuditEvent event : events) {
            if (previous != null) {
                if (!MessageDigest.isEqual(previous.hash().getBytes(StandardCharsets.US_ASCII),
                        event.previousHash().getBytes(StandardCharsets.US_ASCII))) {
                    return AuditChainStatus.broken(verified * 2,
                            "Audit chain link mismatch at sequence " + event.sequence());
                }
                if (event.sequence() != expectedSequence) {
                    return AuditChainStatus.broken(verified * 2,
                            "Audit chain sequence mismatch at sequence " + event.sequence());
                }
            }
            if (event.hash() == null || event.previousHash() == null) {
                return AuditChainStatus.broken(verified * 2, "Audit chain metadata missing");
            }
            String recomputed = AuditHashing.hash(hmacKey, event.sequence(), event.previousHash(), event);
            if (!MessageDigest.isEqual(recomputed.getBytes(StandardCharsets.US_ASCII),
                    event.hash().getBytes(StandardCharsets.US_ASCII))) {
                return AuditChainStatus.broken(verified * 2,
                        "Audit chain hash mismatch at sequence " + event.sequence());
            }
            previous = event;
            expectedSequence = event.sequence() + 1;
            verified++;
        }
        return AuditChainStatus.intact(verified, previous == null ? null : previous.hash());
    }

    @Override
    public synchronized List<AuditEvent> recent(int limit) {
        if (limit <= 0) {
            return List.of();
        }
        List<AuditEvent> result = new ArrayList<>(Math.min(limit, events.size()));
        Iterator<AuditEvent> iterator = events.descendingIterator();
        while (iterator.hasNext() && result.size() < limit) {
            result.add(iterator.next());
        }
        return List.copyOf(result);
    }

    @Override
    public synchronized HealthStatus health() {
        if (closed) {
            return HealthStatus.DOWN;
        }
        return sinkFailure ? HealthStatus.DEGRADED : HealthStatus.UP;
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        for (AuditSink sink : sinks) {
            try {
                sink.flush();
                sink.close();
            } catch (RuntimeException e) {
                LOG.log(System.Logger.Level.WARNING, "Audit sink close failed: {0}", sink.sinkId());
            }
        }
    }

    public synchronized long lastSequence() {
        return sequence;
    }

    public synchronized String lastHash() {
        return lastHash;
    }

    @Override
    public String toString() {
        return "HmacChainedAuditTrail[sinks=" + sinks.size() + ", retained=" + events.size() + "]";
    }
}