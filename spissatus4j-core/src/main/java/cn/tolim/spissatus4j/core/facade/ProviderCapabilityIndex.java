package cn.tolim.spissatus4j.core.facade;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.spi.AlgorithmProvider;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Immutable snapshot of healthy providers per algorithm. */
final class ProviderCapabilityIndex {

    private final Map<AlgorithmId, List<String>> availableProviders;

    private ProviderCapabilityIndex(Map<AlgorithmId, List<String>> availableProviders) {
        this.availableProviders = availableProviders;
    }

    static ProviderCapabilityIndex build(FacadeContext context) {
        ComplianceMode mode = context.complianceMode();
        Map<AlgorithmId, LinkedHashSet<String>> collected = new LinkedHashMap<>();
        for (AlgorithmProvider provider : context.providers()) {
            if (mode == ComplianceMode.FIPS && !provider.fipsCapable()) {
                continue;
            }
            HealthStatus health = context.providerHealth().getOrDefault(
                    provider.providerId(), HealthStatus.UP);
            if (health != HealthStatus.UP) {
                continue;
            }
            Set<AlgorithmId> algorithms;
            try {
                algorithms = Set.copyOf(provider.supportedAlgorithms());
            } catch (RuntimeException e) {
                continue;
            }
            for (AlgorithmId algorithm : algorithms) {
                collected.computeIfAbsent(algorithm, ignored -> new LinkedHashSet<>())
                        .add(provider.providerId());
            }
        }
        Map<AlgorithmId, List<String>> result = new LinkedHashMap<>();
        for (Map.Entry<AlgorithmId, LinkedHashSet<String>> entry : collected.entrySet()) {
            result.put(entry.getKey(), List.copyOf(entry.getValue()));
        }
        return new ProviderCapabilityIndex(Map.copyOf(result));
    }

    boolean hasAvailableProvider(AlgorithmId algorithm) {
        List<String> providers = availableProviders.get(algorithm);
        return providers != null && !providers.isEmpty();
    }

    List<String> providerIds(AlgorithmId algorithm) {
        List<String> providers = availableProviders.get(algorithm);
        return providers == null ? List.of() : providers;
    }
}