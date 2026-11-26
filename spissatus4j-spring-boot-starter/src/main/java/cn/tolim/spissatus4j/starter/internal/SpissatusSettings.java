package cn.tolim.spissatus4j.starter.internal;

import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.starter.properties.SpissatusProperties;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/** Maps Spring configuration properties onto module settings keys. */
public final class SpissatusSettings {

    private SpissatusSettings() {
    }

    public static Map<String, String> settings(SpissatusProperties properties) {
        Objects.requireNonNull(properties, "properties");
        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("spissatus.compliance.mode", properties.getComplianceMode());
        settings.put("spissatus.fail-closed", Boolean.toString(properties.isFailClosed()));
        settings.put("spissatus.fips.enabled", Boolean.toString(properties.getProvider().isFips()));
        settings.put("spissatus.provider.bouncycastle.enabled",
                Boolean.toString(properties.getProvider().isBouncycastle()));
        settings.put("spissatus.provider.gm.enabled",
                Boolean.toString(properties.getProvider().isGm()));
        settings.put("spissatus.crypto.jca.enabled", Boolean.toString(properties.getProvider().isJca()));

        SpissatusProperties.Keys keys = properties.getKeys();
        settings.put("spissatus.key.provider", keys.getProvider());
        putIfPresent(settings, "spissatus.key.file.directory", keys.getFileDirectory());
        putIfPresent(settings, "spissatus.key.master.password", keys.getMasterPassword());
        putIfPresent(settings, "spissatus.key.environment.prefix", keys.getEnvironmentPrefix());
        putIfPresent(settings, "spissatus.key.keystore.path", keys.getKeystorePath());
        putIfPresent(settings, "spissatus.key.keystore.password", keys.getKeystorePassword());
        settings.put("spissatus.key.retain.versions", Integer.toString(keys.getRetainVersions()));

        SpissatusProperties.Policy policy = properties.getPolicy();
        settings.put("spissatus.policy.allow-anonymous", Boolean.toString(policy.isAllowAnonymous()));
        settings.put("spissatus.policy.allowed-callers", csv(policy.getAllowedCallers()));
        settings.put("spissatus.policy.allowed-tenants", csv(policy.getAllowedTenants()));
        settings.put("spissatus.policy.allowed-environments", csv(policy.getAllowedEnvironments()));
        putIfPresent(settings, "spissatus.policy.required-role", policy.getRequiredRole());
        settings.put("spissatus.policy.deny-algorithms", csv(policy.getDenyAlgorithms()));
        settings.put("spissatus.policy.allow-algorithms", csv(policy.getAllowAlgorithms()));
        settings.put("spissatus.policy.cross-tenant-roles", csv(policy.getCrossTenantRoles()));
        settings.put("spissatus.policy.allow-experimental",
                Boolean.toString(policy.isAllowExperimental()));
        settings.put("spissatus.policy.rate-limit-per-minute",
                Integer.toString(policy.getRateLimitPerMinute()));
        settings.put("spissatus.policy.tenant-quota-per-minute",
                Integer.toString(policy.getTenantQuotaPerMinute()));

        SpissatusProperties.Envelope envelope = properties.getEnvelope();
        settings.put("spissatus.envelope.max-bytes", Integer.toString(envelope.getMaxBytes()));

        SpissatusProperties.Nonce nonce = properties.getNonce();
        settings.put("spissatus.nonce.max-entries", Integer.toString(nonce.getMaxEntries()));
        settings.put("spissatus.nonce.ttl-hours", Integer.toString(nonce.getTtlHours()));
        return new RedactedMapView(settings);
    }

    /**
     * Map view whose {@link #toString()} never renders secrets. Entries are
     * still readable by the builder/module wiring code; do not log entry values
     * directly.
     */
    private static final class RedactedMapView extends java.util.AbstractMap<String, String> {
        private final Map<String, String> delegate;

        private RedactedMapView(Map<String, String> delegate) {
            this.delegate = Map.copyOf(delegate);
        }

        @Override
        public java.util.Set<Entry<String, String>> entrySet() {
            return delegate.entrySet();
        }

        @Override
        public String get(Object key) {
            return delegate.get(key);
        }

        @Override
        public boolean containsKey(Object key) {
            return delegate.containsKey(key);
        }

        @Override
        public String toString() {
            return "SpissatusSettings[settings=redacted]";
        }
    }

    public static ComplianceMode complianceMode(SpissatusProperties properties) {
        String value = properties.getComplianceMode();
        if (value == null || value.isBlank()) {
            return ComplianceMode.STANDARD;
        }
        String normalized = value.trim().toUpperCase().replace('-', '_');
        try {
            return ComplianceMode.valueOf(normalized);
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Unsupported compliance mode: " + value);
        }
    }

    /** Safe diagnostic form: never renders secret values. */
    public static String describe(SpissatusProperties properties) {
        return "SpissatusSettings[compliance=" + properties.getComplianceMode()
                + ", keyProvider=" + properties.getKeys().getProvider()
                + ", secrets=redacted]";
    }

    private static void putIfPresent(Map<String, String> settings, String key, String value) {
        if (value != null && !value.isBlank()) {
            settings.put(key, value);
        }
    }

    private static String csv(List<String> values) {
        if (values == null || values.isEmpty()) {
            return "";
        }
        return values.stream().filter(Objects::nonNull).map(String::trim)
                .filter(value -> !value.isEmpty()).collect(Collectors.joining(","));
    }
}