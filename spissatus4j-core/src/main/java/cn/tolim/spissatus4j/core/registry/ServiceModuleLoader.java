package cn.tolim.spissatus4j.core.registry;

import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.Set;

/**
 * Discovers {@link SpissatusModule} implementations and applies the explicit
 * trust policy. Rejected third-party modules are returned (never silently
 * ignored) so the builder can audit and log them.
 */
public final class ServiceModuleLoader {

    public static final String TRUSTED_PREFIX = "cn.tolim.spissatus4j.";

    /** Exact built-in module implementations; no other class is trusted implicitly. */
    private static final Set<String> BUILT_IN_MODULES = Set.of(
            "cn.tolim.spissatus4j.crypto.CryptoModule",
            "cn.tolim.spissatus4j.key.KeyModule",
            "cn.tolim.spissatus4j.envelope.EnvelopeModule",
            "cn.tolim.spissatus4j.policy.PolicyModule",
            "cn.tolim.spissatus4j.audit.AuditModule",
            "cn.tolim.spissatus4j.bc.BouncyCastleModule",
            "cn.tolim.spissatus4j.gm.GmModule");

    private ServiceModuleLoader() {
    }

    public record Result(List<SpissatusModule> modules, List<String> rejectedModuleIds) {
        public Result {
            modules = List.copyOf(modules);
            rejectedModuleIds = List.copyOf(rejectedModuleIds);
        }
    }

    public static Result discover(Set<String> explicitlyTrusted) {
        Objects.requireNonNull(explicitlyTrusted, "explicitlyTrusted");
        List<SpissatusModule> modules = new ArrayList<>();
        List<String> rejected = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        ServiceLoader<SpissatusModule> loader = ServiceLoader.load(SpissatusModule.class,
                Thread.currentThread().getContextClassLoader());
        try {
            for (SpissatusModule module : loader) {
                String moduleId = safeModuleId(module);
                // Trust is anchored on the exact implementation class name. The
                // self-declared module id is never sufficient: a third-party
                // module must be trusted by its fully-qualified class name.
                String className = module.getClass().getName();
                boolean builtIn = BUILT_IN_MODULES.contains(className);
                boolean trusted = builtIn || explicitlyTrusted.contains(className);
                if (!trusted) {
                    rejected.add(moduleId);
                    continue;
                }
                if (!ids.add(moduleId)) {
                    throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                            "Duplicate module id: " + moduleId);
                }
                modules.add(module);
            }
        } catch (ServiceConfigurationError error) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Failed to load spissatus4j modules", error);
        }
        modules.sort(Comparator.comparingInt(SpissatusModule::order)
                .thenComparing(SpissatusModule::moduleId));
        return new Result(modules, rejected);
    }

    private static String safeModuleId(SpissatusModule module) {
        try {
            String id = module.moduleId();
            return id == null ? module.getClass().getName() : id;
        } catch (RuntimeException e) {
            return module.getClass().getName();
        }
    }
}