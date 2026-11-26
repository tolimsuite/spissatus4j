package cn.tolim.spissatus4j.contract.audit;

import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.util.List;

/** Append-only, tamper-evident audit trail. */
public interface AuditTrail {

    AuditEvent append(AuditEvent event);

    default AuditEvent append(AuditEvent.Builder builder) {
        return append(builder.build());
    }

    AuditChainStatus verify();

    List<AuditEvent> recent(int limit);

    HealthStatus health();

    void close();
}