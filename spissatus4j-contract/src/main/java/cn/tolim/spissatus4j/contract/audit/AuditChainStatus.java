package cn.tolim.spissatus4j.contract.audit;

import java.time.Instant;
import java.util.Objects;

/** Result of verifying the HMAC/hash chain over audit records. */
public record AuditChainStatus(boolean intact, long verifiedEvents, String lastHash,
                               String failureReason, Instant checkedAt) {

    public AuditChainStatus {
        Objects.requireNonNull(checkedAt, "checkedAt");
    }

    public static AuditChainStatus intact(long count, String lastHash) {
        return new AuditChainStatus(true, count, lastHash, null, Instant.now());
    }

    public static AuditChainStatus broken(long count, String reason) {
        return new AuditChainStatus(false, count, null, reason, Instant.now());
    }
}