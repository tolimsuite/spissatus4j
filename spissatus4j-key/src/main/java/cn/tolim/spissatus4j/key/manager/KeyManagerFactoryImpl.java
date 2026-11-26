package cn.tolim.spissatus4j.key.manager;

import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyManager;
import cn.tolim.spissatus4j.contract.key.KeyManagerDependencies;
import cn.tolim.spissatus4j.contract.key.KeyManagerFactory;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import cn.tolim.spissatus4j.key.provider.EnvironmentKeyProvider;
import cn.tolim.spissatus4j.key.provider.FileKeyProvider;
import cn.tolim.spissatus4j.key.provider.InMemoryKeyProvider;
import cn.tolim.spissatus4j.key.provider.KeyStoreKeyProvider;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Builds the default key manager from facade settings.
 *
 * <p>Recognized settings: {@code spissatus.key.provider} (memory, file,
 * environment, keystore, provided or module), {@code spissatus.key.provider.id},
 * {@code spissatus.key.file.directory}, {@code spissatus.key.master.password},
 * {@code spissatus.key.environment.prefix}, {@code spissatus.key.keystore.path},
 * {@code spissatus.key.keystore.password} and
 * {@code spissatus.key.retain.versions}. When {@code spissatus.key.provider}
 * is absent and a module contributed exactly one KeyProvider it is used;
 * otherwise the default is the in-memory provider. {@code provided}/{@code module}
 * require exactly one contributed provider (optionally selected by
 * {@code spissatus.key.provider.id}). Explicit memory/file/environment/keystore
 * settings always take precedence. Passwords are never logged or placed in
 * exception messages.</p>
 */
public final class KeyManagerFactoryImpl implements KeyManagerFactory {

    public static final String FACTORY_ID = "default-key-manager";

    public static final String SETTING_PROVIDER = "spissatus.key.provider";
    public static final String SETTING_PROVIDER_ID = "spissatus.key.provider.id";
    public static final String SETTING_FILE_DIRECTORY = "spissatus.key.file.directory";
    public static final String SETTING_MASTER_PASSWORD = "spissatus.key.master.password";
    public static final String SETTING_ENVIRONMENT_PREFIX = "spissatus.key.environment.prefix";
    public static final String SETTING_KEYSTORE_PATH = "spissatus.key.keystore.path";
    public static final String SETTING_KEYSTORE_PASSWORD = "spissatus.key.keystore.password";
    public static final String SETTING_RETAIN_VERSIONS = "spissatus.key.retain.versions";
    public static final String SETTING_CROSS_TENANT_ROLES = "spissatus.policy.cross-tenant-roles";

    @Override
    public String factoryId() {
        return FACTORY_ID;
    }

    @Override
    public KeyManager create(KeyManagerDependencies dependencies) {
        if (dependencies == null) {
            throw new ConfigurationException(ErrorCode.MISSING_DEPENDENCY,
                    "Key manager dependencies are required");
        }
        Map<String, String> settings = dependencies.settings();
        KeyProvider provider = provider(settings, dependencies.keyProviders());
        try {
            return new DefaultKeyManager(provider, dependencies.keyWrappers(),
                    dependencies.policyEngine(), dependencies.auditTrail(), dependencies.clock(),
                    retainVersions(settings), crossTenantRoles(settings));
        } catch (RuntimeException e) {
            try {
                provider.close();
            } catch (RuntimeException ignored) {
                // best effort; preserve the original failure
            }
            throw e;
        }
    }

    private KeyProvider provider(Map<String, String> settings,
                                 List<KeyProvider> contributedProviders) {
        String kind = setting(settings, SETTING_PROVIDER);
        if (kind == null || kind.isBlank()) {
            return contributedProviders.isEmpty()
                    ? new InMemoryKeyProvider()
                    : contributedProvider(settings, contributedProviders);
        }
        if ("provided".equalsIgnoreCase(kind) || "module".equalsIgnoreCase(kind)) {
            return contributedProvider(settings, contributedProviders);
        }
        return switch (kind.toLowerCase(Locale.ROOT)) {
            case "memory" -> new InMemoryKeyProvider();
            case "file" -> {
                String directory = setting(settings, SETTING_FILE_DIRECTORY);
                if (directory == null || directory.isBlank()) {
                    throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                            "spissatus.key.file.directory is required for the file key provider");
                }
                char[] password = requiredPassword(settings, SETTING_MASTER_PASSWORD,
                        "spissatus.key.master.password is required for the file key provider");
                try {
                    yield new FileKeyProvider(path(directory), password);
                } finally {
                    Arrays.fill(password, '\0');
                }
            }
            case "environment" -> {
                String prefix = setting(settings, SETTING_ENVIRONMENT_PREFIX);
                try {
                    yield new EnvironmentKeyProvider(prefix == null || prefix.isBlank()
                            ? EnvironmentKeyProvider.DEFAULT_PREFIX : prefix);
                } catch (IllegalArgumentException e) {
                    throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                            "spissatus.key.environment.prefix is invalid");
                }
            }
            case "keystore" -> {
                String path = setting(settings, SETTING_KEYSTORE_PATH);
                if (path == null || path.isBlank()) {
                    throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                            "spissatus.key.keystore.path is required for the keystore provider");
                }
                char[] password = requiredPassword(settings, SETTING_KEYSTORE_PASSWORD,
                        "spissatus.key.keystore.password is required for the keystore provider");
                try {
                    yield new KeyStoreKeyProvider(path(path), password);
                } finally {
                    Arrays.fill(password, '\0');
                }
            }
            default -> throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Unknown spissatus.key.provider value");
        };
    }

    /**
     * Selects exactly one module-contributed provider. An optional
     * {@code spissatus.key.provider.id} narrows the candidate set by
     * provider id. Zero or multiple matches fail closed.
     */
    private KeyProvider contributedProvider(Map<String, String> settings,
                                            List<KeyProvider> contributedProviders) {
        String requestedId = setting(settings, SETTING_PROVIDER_ID);
        List<KeyProvider> candidates = contributedProviders.stream()
                .filter(provider -> requestedId == null || requestedId.isBlank()
                        || requestedId.equals(provider.providerId()))
                .toList();
        if (candidates.size() != 1) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    requestedId == null || requestedId.isBlank()
                            ? "Exactly one contributed key provider is required"
                            : "No unique contributed key provider matches spissatus.key.provider.id");
        }
        return candidates.get(0);
    }

    private int retainVersions(Map<String, String> settings) {
        String raw = setting(settings, SETTING_RETAIN_VERSIONS);
        if (raw == null || raw.isBlank()) {
            return 3;
        }
        int value;
        try {
            value = Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "spissatus.key.retain.versions must be an integer");
        }
        if (value < 1 || value > 1000) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "spissatus.key.retain.versions must be between 1 and 1000");
        }
        return value;
    }

    private static char[] requiredPassword(Map<String, String> settings, String key,
                                           String message) {
        String value = settings.get(key);
        if (value == null || value.isEmpty() || value.isBlank()) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID, message);
        }
        return value.toCharArray();
    }

    private java.util.Set<String> crossTenantRoles(Map<String, String> settings) {
        String raw = setting(settings, SETTING_CROSS_TENANT_ROLES);
        if (raw == null || raw.isBlank()) {
            return java.util.Set.of("crypto-cross-tenant", "crypto-admin");
        }
        java.util.LinkedHashSet<String> roles = new java.util.LinkedHashSet<>();
        for (String value : raw.split(",")) {
            String role = value.trim();
            if (!role.isEmpty()) {
                roles.add(role);
            }
        }
        if (roles.isEmpty()) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    SETTING_CROSS_TENANT_ROLES + " must contain at least one role");
        }
        return java.util.Set.copyOf(roles);
    }

    private static String setting(Map<String, String> settings, String key) {
        String value = settings.get(key);
        return value == null ? null : value.trim();
    }

    private static Path path(String value) {
        try {
            return Path.of(value);
        } catch (InvalidPathException e) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Configured key storage path is invalid");
        }
    }
}