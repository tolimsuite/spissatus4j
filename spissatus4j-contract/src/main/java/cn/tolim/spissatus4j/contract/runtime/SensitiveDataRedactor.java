package cn.tolim.spissatus4j.contract.runtime;

/**
 * Redacts secrets from log lines, audit details, exception messages and
 * metric tags. Implementations must be safe to call from any thread and must
 * never echo the original value.
 */
public interface SensitiveDataRedactor {

    String redact(String text);

    /** Renders a labelled value for diagnostics without disclosing it. */
    String redactValue(String label, String value);
}