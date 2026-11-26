package cn.tolim.spissatus4j.policy;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.policy.PolicyRule;
import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import cn.tolim.spissatus4j.policy.access.DefaultAccessPolicy;
import cn.tolim.spissatus4j.policy.algorithm.DefaultAlgorithmPolicy;
import cn.tolim.spissatus4j.policy.decision.ComplianceRule;
import cn.tolim.spissatus4j.policy.decision.DefaultPolicyEngine;
import cn.tolim.spissatus4j.policy.tenant.DefaultTenantPolicy;
import cn.tolim.spissatus4j.policy.usage.DefaultUsagePolicy;

import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Service-loader module contributing the default policy engine.
 *
 * <p>Settings read (all optional, defaults shown):</p>
 * <ul>
 *   <li>{@code spissatus.policy.allow-anonymous=false}</li>
 *   <li>{@code spissatus.policy.allowed-callers} (CSV, empty = any authenticated caller)</li>
 *   <li>{@code spissatus.policy.allowed-tenants} (CSV, empty = any)</li>
 *   <li>{@code spissatus.policy.allowed-environments} (CSV, empty = any)</li>
 *   <li>{@code spissatus.policy.required-role} (empty = none)</li>
 *   <li>{@code spissatus.policy.deny-algorithms} (CSV of algorithm ids)</li>
 *   <li>{@code spissatus.policy.allow-algorithms} (CSV whitelist; non-empty = only these)</li>
 *   <li>{@code spissatus.policy.allow-experimental=false}</li>
 *   <li>{@code spissatus.policy.rate-limit-per-minute=0} (0 = disabled, per caller)</li>
 *   <li>{@code spissatus.policy.tenant-quota-per-minute=0} (0 = disabled)</li>
 *   <li>{@code spissatus.compliance.mode=STANDARD}</li>
 * </ul>
 *
 * <p>The module only registers the engine; it never reads key material and has
 * no other side effects.</p>
 */
public final class PolicyModule implements SpissatusModule {

    public static final String MODULE_ID = "policy";
    public static final int MODULE_ORDER = 150;
    public static final String ENGINE_ID = "policy";

    private static final String PREFIX = "spissatus.policy.";
    private static final String ALLOW_ANONYMOUS = PREFIX + "allow-anonymous";
    private static final String ALLOWED_CALLERS = PREFIX + "allowed-callers";
    private static final String ALLOWED_TENANTS = PREFIX + "allowed-tenants";
    private static final String ALLOWED_ENVIRONMENTS = PREFIX + "allowed-environments";
    private static final String REQUIRED_ROLE = PREFIX + "required-role";
    private static final String DENY_ALGORITHMS = PREFIX + "deny-algorithms";
    private static final String ALLOW_ALGORITHMS = PREFIX + "allow-algorithms";
    private static final String ALLOW_EXPERIMENTAL = PREFIX + "allow-experimental";
    private static final String RATE_LIMIT = PREFIX + "rate-limit-per-minute";
    private static final String TENANT_QUOTA = PREFIX + "tenant-quota-per-minute";
    private static final String CROSS_TENANT_ROLES = PREFIX + "cross-tenant-roles";
    private static final String COMPLIANCE_MODE = "spissatus.compliance.mode";

    @Override
    public String moduleId() {
        return MODULE_ID;
    }

    @Override
    public int order() {
        return MODULE_ORDER;
    }

    @Override
    public void contribute(ModuleContext context) {
        Objects.requireNonNull(context, "context");
        boolean allowAnonymous = booleanSetting(context, ALLOW_ANONYMOUS, false);
        Set<String> allowedCallers = csvSetting(context, ALLOWED_CALLERS);
        Set<String> allowedTenants = csvSetting(context, ALLOWED_TENANTS);
        Set<String> allowedEnvironments = csvSetting(context, ALLOWED_ENVIRONMENTS);
        String requiredRole = context.setting(REQUIRED_ROLE).map(String::trim).orElse("");
        Set<AlgorithmId> deniedAlgorithms = algorithmSetting(context, DENY_ALGORITHMS);
        Set<AlgorithmId> allowedAlgorithms = algorithmSetting(context, ALLOW_ALGORITHMS);
        boolean allowExperimental = booleanSetting(context, ALLOW_EXPERIMENTAL, false);
        int rateLimit = intSetting(context, RATE_LIMIT, 0);
        int tenantQuota = intSetting(context, TENANT_QUOTA, 0);
        ComplianceMode complianceMode = complianceMode(context);

        List<PolicyRule> rules = new ArrayList<>();
        rules.add(new DefaultAccessPolicy(allowAnonymous, allowedCallers, requiredRole,
                allowedEnvironments, rateLimit, tenantQuota, Clock.systemUTC()));
        rules.add(new DefaultTenantPolicy(allowedTenants, crossTenantRoles(context)));
        rules.add(new DefaultAlgorithmPolicy(allowedAlgorithms, deniedAlgorithms, allowExperimental));
        rules.add(new DefaultUsagePolicy());
        rules.add(new ComplianceRule(complianceMode));

        context.registerPolicyEngine(new DefaultPolicyEngine(List.copyOf(rules), List.of(), ENGINE_ID));
    }

    private static boolean booleanSetting(ModuleContext context, String key, boolean defaultValue) {
        Optional<String> value = context.setting(key);
        if (value.isEmpty() || value.get().isBlank()) {
            return defaultValue;
        }
        String text = value.get().trim();
        if ("true".equalsIgnoreCase(text)) {
            return true;
        }
        if ("false".equalsIgnoreCase(text)) {
            return false;
        }
        throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                "Setting " + key + " must be true or false");
    }

    private static int intSetting(ModuleContext context, String key, int defaultValue) {
        Optional<String> value = context.setting(key);
        if (value.isEmpty() || value.get().isBlank()) {
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(value.get().trim());
            if (parsed < 0) {
                throw new NumberFormatException("negative");
            }
            return parsed;
        } catch (NumberFormatException failure) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Setting " + key + " must be a non-negative integer");
        }
    }

    private static Set<String> crossTenantRoles(ModuleContext context) {
        Set<String> roles = csvSetting(context, CROSS_TENANT_ROLES);
        return roles.isEmpty() ? Set.of("crypto-cross-tenant", "crypto-admin") : roles;
    }

    private static Set<String> csvSetting(ModuleContext context, String key) {
        Optional<String> value = context.setting(key);
        if (value.isEmpty() || value.get().isBlank()) {
            return Set.of();
        }
        LinkedHashSet<String> result = new LinkedHashSet<>();
        for (String part : value.get().split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return Set.copyOf(result);
    }

    private static Set<AlgorithmId> algorithmSetting(ModuleContext context, String key) {
        Set<String> ids = csvSetting(context, key);
        if (ids.isEmpty()) {
            return Set.of();
        }
        LinkedHashSet<AlgorithmId> result = new LinkedHashSet<>();
        for (String id : ids) {
            try {
                result.add(AlgorithmId.of(id));
            } catch (IllegalArgumentException failure) {
                throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                        "Setting " + key + " contains an invalid algorithm identifier");
            }
        }
        return Set.copyOf(result);
    }

    private static ComplianceMode complianceMode(ModuleContext context) {
        Optional<String> value = context.setting(COMPLIANCE_MODE);
        if (value.isEmpty() || value.get().isBlank()) {
            return ComplianceMode.STANDARD;
        }
        String text = value.get().trim().toUpperCase(Locale.ROOT);
        try {
            return ComplianceMode.valueOf(text);
        } catch (IllegalArgumentException failure) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Setting " + COMPLIANCE_MODE + " must be STANDARD, FIPS, GM or GM_HYBRID");
        }
    }

    /** Non-sensitive settings keys consumed by this module with their defaults. */
    public static Map<String, String> settingDefaults() {
        return Map.ofEntries(
                Map.entry(ALLOW_ANONYMOUS, "false"),
                Map.entry(ALLOWED_CALLERS, ""),
                Map.entry(ALLOWED_TENANTS, ""),
                Map.entry(ALLOWED_ENVIRONMENTS, ""),
                Map.entry(REQUIRED_ROLE, ""),
                Map.entry(DENY_ALGORITHMS, ""),
                Map.entry(ALLOW_ALGORITHMS, ""),
                Map.entry(ALLOW_EXPERIMENTAL, "false"),
                Map.entry(RATE_LIMIT, "0"),
                Map.entry(TENANT_QUOTA, "0"),
                Map.entry(COMPLIANCE_MODE, "STANDARD"));
    }
}