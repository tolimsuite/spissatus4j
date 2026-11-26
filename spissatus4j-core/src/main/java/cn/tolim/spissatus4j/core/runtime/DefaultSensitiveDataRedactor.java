package cn.tolim.spissatus4j.core.runtime;

import cn.tolim.spissatus4j.contract.runtime.SensitiveDataRedactor;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Conservative log/audit redactor. It removes common secret assignments and
 * PEM blocks and never echoes the original secret. Over-redaction is
 * preferred to leaking.
 */
public final class DefaultSensitiveDataRedactor implements SensitiveDataRedactor {

    private static final Pattern PEM = Pattern.compile(
            "-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----", Pattern.DOTALL);
    private static final Pattern ASSIGNMENT = Pattern.compile(
            "(?i)\\b(password|passphrase|secret|token|credential|private[_-]?key|api[_-]?key|"
                    + "master[_-]?key|dek|kek)\\b(\\s*[=:]\\s*)(\"[^\"]*\"|'[^']*'|[^\\s,;]+)");
    private static final Pattern MAX = Pattern.compile("[\\r\\n\\t]");

    @Override
    public String redact(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String result = PEM.matcher(text).replaceAll("[REDACTED-PEM]");
        Matcher matcher = ASSIGNMENT.matcher(result);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            matcher.appendReplacement(sb, Matcher.quoteReplacement(
                    matcher.group(1) + matcher.group(2) + "[REDACTED]"));
        }
        matcher.appendTail(sb);
        return MAX.matcher(sb.toString()).replaceAll(" ");
    }

    @Override
    public String redactValue(String label, String value) {
        Objects.requireNonNull(label, "label");
        String safeLabel = label.replaceAll("[^A-Za-z0-9_.-]", "_");
        if (safeLabel.length() > 64) {
            safeLabel = safeLabel.substring(0, 64);
        }
        return safeLabel + "=[REDACTED len=" + (value == null ? 0 : value.length()) + "]";
    }
}