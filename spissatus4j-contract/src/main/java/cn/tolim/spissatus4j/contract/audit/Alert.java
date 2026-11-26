package cn.tolim.spissatus4j.contract.audit;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Operational alert (algorithm downgrade, nonce reuse, decryption failure
 * spike, key expiry, audit chain break). Content must be non-sensitive.
 */
public record Alert(Instant timestamp, AlertSeverity severity, String code,
                    String message, Map<String, String> tags) {

    public Alert {
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(code, "code");
        message = Objects.requireNonNull(message, "message");
        tags = Map.copyOf(Objects.requireNonNull(tags, "tags"));
    }

    public static Alert of(AlertSeverity severity, String code, String message) {
        return new Alert(Instant.now(), severity, code, message, Map.of());
    }
}