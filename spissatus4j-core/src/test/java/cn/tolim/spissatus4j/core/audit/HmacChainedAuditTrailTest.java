package cn.tolim.spissatus4j.core.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.audit.AuditChainStatus;
import cn.tolim.spissatus4j.contract.audit.AuditEvent;
import cn.tolim.spissatus4j.contract.audit.AuditEventType;
import cn.tolim.spissatus4j.contract.audit.AuditOutcome;
import cn.tolim.spissatus4j.contract.audit.AuditSeverity;
import cn.tolim.spissatus4j.contract.audit.AuditSink;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.lang.reflect.Field;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class HmacChainedAuditTrailTest {

    private static SecretKeySpec key() {
        byte[] bytes = new byte[32];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) i;
        }
        return new SecretKeySpec(bytes, "HmacSHA256");
    }

    private static AuditEvent event(int index) {
        return AuditEvent.builder(AuditEventType.ENCRYPT, AuditSeverity.INFO, AuditOutcome.SUCCESS)
                .callerId("tester").tenantId("tenant-a")
                .algorithm(AlgorithmId.AES_GCM).operation(Operation.ENCRYPT)
                .message("event " + index)
                .detail("index", Integer.toString(index))
                .detail("alpha", "one")
                .detail("beta", "two")
                .build();
    }

    @Test
    void appendsAndVerifiesAChain() {
        InMemoryAuditSink sink = new InMemoryAuditSink(100);
        HmacChainedAuditTrail trail = new HmacChainedAuditTrail(List.of(sink), key(), 100);
        for (int i = 0; i < 50; i++) {
            trail.append(event(i));
        }
        assertEquals(50, sink.size());
        AuditChainStatus status = trail.verify();
        assertTrue(status.intact());
        assertEquals(50, status.verifiedEvents());
        assertEquals(50, trail.lastSequence());
        assertEquals(50, trail.recent(100).size());
        assertEquals("event 49", trail.recent(1).getFirst().message());
        assertTrue(trail.health() == HealthStatus.UP);
        trail.close();
    }

    @Test
    void detectsTamperedRetainedEvent() throws Exception {
        HmacChainedAuditTrail trail = new HmacChainedAuditTrail(List.of(), key(), 100);
        for (int i = 0; i < 5; i++) {
            trail.append(event(i));
        }
        Field field = HmacChainedAuditTrail.class.getDeclaredField("events");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        Deque<AuditEvent> events = (Deque<AuditEvent>) field.get(trail);
        AuditEvent last = events.removeLast();
        events.addLast(last.toBuilder().message("forged").build());
        AuditChainStatus status = trail.verify();
        assertFalse(status.intact());
        assertTrue(status.failureReason().contains("hash mismatch"));
    }

    @Test
    void detectsDeletedMiddleEvent() throws Exception {
        HmacChainedAuditTrail trail = new HmacChainedAuditTrail(List.of(), key(), 100);
        for (int i = 0; i < 5; i++) {
            trail.append(event(i));
        }
        Field field = HmacChainedAuditTrail.class.getDeclaredField("events");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        Deque<AuditEvent> events = (Deque<AuditEvent>) field.get(trail);
        var iterator = events.iterator();
        iterator.next();
        iterator.next();
        iterator.next();
        iterator.remove();
        AuditChainStatus status = trail.verify();
        assertFalse(status.intact());
    }

    @Test
    void sinkFailureDegradesHealthAndKeepsOtherSinks() {
        List<AuditEvent> received = new ArrayList<>();
        AuditSink good = new AuditSink() {
            @Override
            public String sinkId() {
                return "good";
            }

            @Override
            public void write(AuditEvent event) {
                received.add(event);
            }

            @Override
            public HealthStatus health() {
                return HealthStatus.UP;
            }
        };
        AuditSink bad = new AuditSink() {
            @Override
            public String sinkId() {
                return "bad";
            }

            @Override
            public void write(AuditEvent event) {
                throw new IllegalStateException("disk full");
            }

            @Override
            public HealthStatus health() {
                return HealthStatus.DOWN;
            }
        };
        HmacChainedAuditTrail trail = new HmacChainedAuditTrail(List.of(bad, good), key(), 10);
        trail.append(event(1));
        assertEquals(1, received.size());
        assertEquals(HealthStatus.DEGRADED, trail.health());
        assertTrue(trail.verify().intact());
    }

    @Test
    void detectsTruncatedLeadingEventsBeforeEviction() throws Exception {
        HmacChainedAuditTrail trail = new HmacChainedAuditTrail(List.of(), key(), 100);
        for (int i = 0; i < 5; i++) {
            trail.append(event(i));
        }
        Field field = HmacChainedAuditTrail.class.getDeclaredField("events");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        Deque<AuditEvent> events = (Deque<AuditEvent>) field.get(trail);
        events.removeFirst();
        assertFalse(trail.verify().intact());
        events.clear();
        assertFalse(trail.verify().intact());
    }

    @Test
    void boundsRetainedEvents() {
        HmacChainedAuditTrail trail = new HmacChainedAuditTrail(List.of(), key(), 3);
        for (int i = 0; i < 10; i++) {
            trail.append(event(i));
        }
        assertEquals(3, trail.recent(100).size());
        AuditChainStatus status = trail.verify();
        assertTrue(status.intact());
        assertEquals(3, status.verifiedEvents());
    }

    @Test
    void toStringDoesNotRevealTheKey() {
        HmacChainedAuditTrail trail = new HmacChainedAuditTrail(List.of(new InMemoryAuditSink(1)), key(), 1);
        String text = trail.toString();
        assertFalse(text.contains("0b0b"));
        assertFalse(text.contains("SecretKey"));
        assertFalse(text.contains("bytes["));
    }
}