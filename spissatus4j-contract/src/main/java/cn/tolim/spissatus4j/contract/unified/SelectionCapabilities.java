package cn.tolim.spissatus4j.contract.unified;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmCatalog;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmFamily;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmInfo;
import cn.tolim.spissatus4j.contract.api.Capabilities;
import cn.tolim.spissatus4j.contract.compliance.ComplianceMode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/** Capability snapshot used to explain unified algorithm selection. */
public record SelectionCapabilities(
        String serviceVersion,
        ComplianceMode complianceMode,
        List<AlgorithmCandidate> candidates,
        List<SelectionProfile> profiles) {

    public SelectionCapabilities {
        serviceVersion = Objects.requireNonNull(serviceVersion, "serviceVersion");
        Objects.requireNonNull(complianceMode, "complianceMode");
        candidates = List.copyOf(Objects.requireNonNull(candidates, "candidates"));
        profiles = List.copyOf(Objects.requireNonNull(profiles, "profiles"));
    }

    /** Derives the unified capability view without exposing provider types. */
    public static SelectionCapabilities from(Capabilities capabilities) {
        Objects.requireNonNull(capabilities, "capabilities");
        ComplianceMode mode = capabilities.complianceMode();
        List<AlgorithmId> order = SelectionProfile.defaultFor(mode).defaultOrder(mode);
        List<AlgorithmCandidate> candidates = new ArrayList<>();
        for (AlgorithmInfo info : AlgorithmCatalog.all()) {
            if (!isEncryptionFamily(info.family())) {
                continue;
            }
            boolean installed = capabilities.supportedAlgorithms().contains(info.id());
            boolean compliant = mode.allows(info);
            boolean healthy = capabilities.providers().stream()
                    .anyMatch(provider -> provider.health() == HealthStatus.UP
                            && provider.algorithms().contains(info.id()));
            int rank = order.indexOf(info.id());
            candidates.add(new AlgorithmCandidate(info, installed, compliant,
                    installed && compliant && healthy, rank));
        }
        candidates.sort(Comparator
                .comparingInt((AlgorithmCandidate candidate) ->
                        candidate.rank() < 0 ? Integer.MAX_VALUE : candidate.rank())
                .thenComparing(candidate -> candidate.info().id().id()));
        List<SelectionProfile> profiles = new ArrayList<>();
        for (SelectionProfile profile : SelectionProfile.values()) {
            if (profile.allowedIn(mode)) {
                profiles.add(profile);
            }
        }
        return new SelectionCapabilities(capabilities.serviceVersion(), mode,
                List.copyOf(candidates), List.copyOf(profiles));
    }

    private static boolean isEncryptionFamily(AlgorithmFamily family) {
        // Unified v2 envelopes authenticate metadata through AEAD/EtM AAD only;
        // asymmetric algorithms are not unified-entry capabilities.
        return family == AlgorithmFamily.AEAD || family == AlgorithmFamily.SYMMETRIC;
    }
}