package cn.tolim.spissatus4j.contract.key;

import cn.tolim.spissatus4j.contract.audit.AuditTrail;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.spi.KeyProvider;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Dependencies supplied by the facade builder to a {@link KeyManagerFactory}.
 *
 * <p>Module-contributed {@link KeyProvider}s are offered here so an extension
 * module (HSM, Vault, KMS) can be wired without the core knowing concrete
 * providers. The factory chooses one according to its settings.</p>
 *
 * <p>Settings may contain secrets. {@link #toString()} deliberately omits
 * them; never log the raw settings map.</p>
 */
public record KeyManagerDependencies(
        PolicyEngine policyEngine,
        AuditTrail auditTrail,
        Clock clock,
        List<KeyWrapper> keyWrappers,
        List<KeyProvider> keyProviders,
        Map<String, String> settings) {

    public KeyManagerDependencies {
        Objects.requireNonNull(policyEngine, "policyEngine");
        Objects.requireNonNull(auditTrail, "auditTrail");
        Objects.requireNonNull(clock, "clock");
        keyWrappers = List.copyOf(Objects.requireNonNull(keyWrappers, "keyWrappers"));
        keyProviders = List.copyOf(Objects.requireNonNull(keyProviders, "keyProviders"));
        settings = Map.copyOf(Objects.requireNonNull(settings, "settings"));
    }

    /** Compatibility constructor for factories that do not consume providers. */
    public KeyManagerDependencies(PolicyEngine policyEngine, AuditTrail auditTrail, Clock clock,
                                  List<KeyWrapper> keyWrappers, Map<String, String> settings) {
        this(policyEngine, auditTrail, clock, keyWrappers, List.of(), settings);
    }

    @Override
    public String toString() {
        return "KeyManagerDependencies[policyEngine=" + policyEngine.engineId()
                + ", keyWrappers=" + keyWrappers.size()
                + ", keyProviders=" + keyProviders.size()
                + ", settings=redacted]";
    }
}