package cn.tolim.spissatus4j.core.policy;

import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyProvider;
import cn.tolim.spissatus4j.contract.policy.PolicyRule;
import cn.tolim.spissatus4j.contract.policy.PolicySnapshot;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;
import cn.tolim.spissatus4j.contract.policy.SelectionHints;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Wraps the base policy engine with rules loaded from module-contributed
 * {@link PolicyProvider}s. Provider failures and refresh failures fail closed
 * and are never silently ignored.
 */
public final class ContributorPolicyEngine implements PolicyEngine {

    private final PolicyEngine base;
    private final List<PolicyProvider> providers;
    private final Set<String> failedProviders = ConcurrentHashMap.newKeySet();

    public ContributorPolicyEngine(PolicyEngine base, List<PolicyProvider> providers) {
        this.base = Objects.requireNonNull(base, "base");
        this.providers = List.copyOf(Objects.requireNonNull(providers, "providers"));
    }

    @Override
    public String engineId() {
        return "composite(" + base.engineId() + ")";
    }

    @Override
    public PolicyDecision evaluate(cn.tolim.spissatus4j.contract.policy.PolicyRequest request) {
        PolicyDecision decision = base.evaluate(request);
        for (PolicyProvider provider : providers) {
            String id = providerId(provider);
            if (failedProviders.contains(id)) {
                return deny(id, "Policy provider refresh failed");
            }
            try {
                HealthStatus health = provider.health();
                if (health == null || health == HealthStatus.DOWN) {
                    return deny(id, "Policy provider is unavailable");
                }
                PolicySnapshot snapshot = provider.load();
                if (snapshot == null) {
                    failedProviders.add(id);
                    return deny(id, "Policy provider returned no snapshot");
                }
                for (PolicyRule rule : snapshot.rules()) {
                    if (rule == null) {
                        return deny(id, "Policy provider returned an invalid rule");
                    }
                    HealthStatus ruleHealth = rule.health();
                    if (ruleHealth == null || ruleHealth == HealthStatus.DOWN) {
                        return deny(id, "Policy rule is unavailable");
                    }
                    PolicyDecision providerDecision = rule.evaluate(request);
                    if (providerDecision == null) {
                        return deny(id, "Policy rule returned no decision");
                    }
                    decision = PolicyDecision.strictest(decision, providerDecision);
                }
            } catch (RuntimeException e) {
                failedProviders.add(id);
                return deny(id, "Policy provider failed");
            }
        }
        return DecisionDefaults.ensure(decision);
    }

    private static PolicyDecision deny(String providerId, String message) {
        return PolicyDecision.deny(ReasonCodes.POLICY_UNAVAILABLE, message,
                "provider." + providerId);
    }

    private static String providerId(PolicyProvider provider) {
        try {
            String id = provider.providerId();
            return id == null || id.isBlank() ? "unknown" : id;
        } catch (RuntimeException e) {
            return "unknown";
        }
    }

    @Override
    public SelectionHints selectionHints(CallerContext caller) {
        try {
            return base.selectionHints(caller);
        } catch (RuntimeException e) {
            // Hints are non-authoritative; the authoritative evaluate call fails closed.
            return SelectionHints.none();
        }
    }

    @Override
    public HealthStatus health() {
        HealthStatus result = healthOf(base::health);
        for (PolicyProvider provider : providers) {
            if (failedProviders.contains(providerId(provider))) {
                return HealthStatus.DOWN;
            }
            result = worst(result, healthOf(() -> provider.health()));
        }
        return result;
    }

    @Override
    public void refresh() {
        base.refresh();
        for (PolicyProvider provider : providers) {
            String id = providerId(provider);
            try {
                provider.refresh();
                failedProviders.remove(id);
            } catch (RuntimeException e) {
                failedProviders.add(id);
            }
        }
    }

    private static HealthStatus healthOf(java.util.function.Supplier<HealthStatus> supplier) {
        try {
            HealthStatus status = supplier.get();
            return status == null ? HealthStatus.DOWN : status;
        } catch (RuntimeException e) {
            return HealthStatus.DOWN;
        }
    }

    private static HealthStatus worst(HealthStatus left, HealthStatus right) {
        if (left == HealthStatus.DOWN || right == HealthStatus.DOWN) {
            return HealthStatus.DOWN;
        }
        if (left == HealthStatus.DEGRADED || right == HealthStatus.DEGRADED) {
            return HealthStatus.DEGRADED;
        }
        return HealthStatus.UP;
    }

    public List<PolicyProvider> providers() {
        return providers;
    }

    public List<String> providerIds() {
        List<String> ids = new ArrayList<>(providers.size());
        for (PolicyProvider provider : providers) {
            ids.add(providerId(provider));
        }
        return List.copyOf(ids);
    }

    private static final class DecisionDefaults {
        private DecisionDefaults() {
        }

        static PolicyDecision ensure(PolicyDecision decision) {
            return decision == null
                    ? deny("base", "Policy evaluation unavailable")
                    : decision;
        }
    }
}