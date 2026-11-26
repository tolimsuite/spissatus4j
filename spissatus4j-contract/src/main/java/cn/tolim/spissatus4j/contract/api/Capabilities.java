package cn.tolim.spissatus4j.contract.api;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Snapshot of installed providers, supported algorithms and compliance mode. */
public record Capabilities(
        String serviceVersion,
        Set<AlgorithmId> supportedAlgorithms,
        List<ProviderCapability> providers,
        ComplianceMode complianceMode,
        boolean fipsAvailable,
        boolean gmAvailable,
        HealthStatus health) {

    public Capabilities {
        Objects.requireNonNull(serviceVersion, "serviceVersion");
        supportedAlgorithms = Set.copyOf(Objects.requireNonNull(supportedAlgorithms, "supportedAlgorithms"));
        providers = List.copyOf(Objects.requireNonNull(providers, "providers"));
        Objects.requireNonNull(complianceMode, "complianceMode");
        Objects.requireNonNull(health, "health");
    }

    public boolean supports(AlgorithmId algorithm) {
        return supportedAlgorithms.contains(algorithm);
    }

    /** Capability view of one provider. */
    public record ProviderCapability(String providerId, int priority, Set<AlgorithmId> algorithms,
                                     HealthStatus health) {

        public ProviderCapability {
            Objects.requireNonNull(providerId, "providerId");
            algorithms = Set.copyOf(Objects.requireNonNull(algorithms, "algorithms"));
            Objects.requireNonNull(health, "health");
        }
    }
}