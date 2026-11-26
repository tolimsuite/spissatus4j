package cn.tolim.spissatus4j.core.audit;

import cn.tolim.spissatus4j.contract.audit.Alert;
import cn.tolim.spissatus4j.contract.audit.AlertSeverity;
import cn.tolim.spissatus4j.contract.audit.AlertSink;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.util.Map;

/** Last-resort alert sink that logs sanitized alerts through java.util.logging. */
public final class LoggingAlertSink implements AlertSink {

    private static final System.Logger LOG = System.getLogger(LoggingAlertSink.class.getName());

    @Override
    public String sinkId() {
        return "logging";
    }

    @Override
    public void raise(Alert alert) {
        if (alert == null) {
            return;
        }
        String message = sanitize(alert.message());
        StringBuilder tags = new StringBuilder();
        for (Map.Entry<String, String> entry : alert.tags().entrySet().stream()
                .sorted(Map.Entry.comparingByKey()).toList()) {
            tags.append(' ').append(sanitize(entry.getKey())).append('=').append(sanitize(entry.getValue()));
        }
        String line = alert.code() + " " + message + tags;
        System.Logger.Level level = alert.severity() == AlertSeverity.CRITICAL
                || alert.severity() == AlertSeverity.HIGH
                ? System.Logger.Level.ERROR : System.Logger.Level.WARNING;
        LOG.log(level, line);
    }

    private static String sanitize(String value) {
        if (value == null) {
            return "";
        }
        String cleaned = value.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ');
        return cleaned.length() > 512 ? cleaned.substring(0, 512) : cleaned;
    }

    @Override
    public HealthStatus health() {
        return HealthStatus.UP;
    }
}