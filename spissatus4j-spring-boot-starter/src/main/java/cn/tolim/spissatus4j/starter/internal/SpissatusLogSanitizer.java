package cn.tolim.spissatus4j.starter.internal;

import cn.tolim.spissatus4j.contract.runtime.SensitiveDataRedactor;
import java.util.Objects;

/**
 * Logging helper that applies the configured sensitive-data redactor. Wire it
 * into the logging pattern (for example with a Logback conversion rule) or
 * call it before writing security diagnostics.
 *
 * <p>This class deliberately provides an explicit API rather than mutating the
 * host application's logging configuration, which a library must not do.</p>
 */
public final class SpissatusLogSanitizer {

    private final SensitiveDataRedactor redactor;

    public SpissatusLogSanitizer(SensitiveDataRedactor redactor) {
        this.redactor = Objects.requireNonNull(redactor, "redactor");
    }

    public String sanitize(String message) {
        return redactor.redact(message);
    }

    public String describeValue(String label, String value) {
        return redactor.redactValue(label, value);
    }
}