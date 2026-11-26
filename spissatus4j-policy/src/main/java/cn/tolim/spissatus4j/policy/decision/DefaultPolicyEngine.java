package cn.tolim.spissatus4j.policy.decision;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmCatalog;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmInfo;
import cn.tolim.spissatus4j.contract.policy.AlgorithmPolicy;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyEngine;
import cn.tolim.spissatus4j.contract.policy.PolicyProvider;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.PolicyRule;
import cn.tolim.spissatus4j.contract.policy.PolicySnapshot;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;
import cn.tolim.spissatus4j.contract.policy.SelectionHints;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Unified, fail-closed policy engine.
 *
 * <p>Every configured rule and every rule loaded from a {@link PolicyProvider}
 * snapshot is evaluated and combined with strictest-wins semantics. Any rule
 * or provider failure, any DOWN health, a provider whose last refresh failed
 * (until a successful refresh clears it), a missing snapshot or a rule that
 * returns {@code null} produces {@code DENY POLICY_UNAVAILABLE}; the engine
 * never throws from {@link #evaluate(PolicyRequest)}.</p>
 *
 * <p>Provider snapshots are loaded on every evaluation and are treated as
 * untrusted data: null snapshots, null rules and provider exceptions all fail
 * closed. The engine itself is immutable apart from refresh-failure tracking,
 * so a single instance may be shared between threads; rule instances must be
 * thread-safe if shared.</p>
 */
public final class DefaultPolicyEngine implements PolicyEngine {

    /** Engine identifier used by the convenience constructor. */
    public static final String DEFAULT_ENGINE_ID = "policy";

    private static final String FALLBACK_RULE_ID = "policy-rule";
    private static final String FALLBACK_PROVIDER_ID = "policy-provider";

    private final List<PolicyRule> rules;
    private final List<PolicyProvider> providers;
    private final String engineId;
    private final Set<String> failedProviderRefreshes = ConcurrentHashMap.newKeySet();

    /**
     * Creates an engine.
     *
     * @param rules locally configured rules; {@code null} is treated as empty
     * @param providers external policy sources; {@code null} is treated as empty
     * @param engineId stable, non-sensitive engine identifier
     * @throws IllegalArgumentException if the engine identifier is blank
     */
    public DefaultPolicyEngine(List<PolicyRule> rules, List<PolicyProvider> providers, String engineId) {
        this.rules = List.copyOf(copyRules(rules));
        this.providers = List.copyOf(copyProviders(providers));
        String id = Objects.requireNonNull(engineId, "engineId").trim();
        if (id.isEmpty()) {
            throw new IllegalArgumentException("engineId must not be blank");
        }
        this.engineId = id;
    }

    /**
     * Creates an engine without external policy providers.
     *
     * @param rules locally configured rules
     */
    public DefaultPolicyEngine(List<PolicyRule> rules) {
        this(rules, List.of(), DEFAULT_ENGINE_ID);
    }

    @Override
    public String engineId() {
        return engineId;
    }

    /** Returns the immutable local rule list. */
    public List<PolicyRule> rules() {
        return rules;
    }

    /** Returns the immutable provider list. */
    public List<PolicyProvider> providers() {
        return providers;
    }

    /**
     * Returns non-authoritative selection hints derived only from the locally
     * configured rules.
     *
     * <p>This method is side-effect-free: it never calls
     * {@link PolicyProvider#load()}, {@link PolicyProvider#refresh()},
     * {@link PolicyProvider#health()}, {@link PolicyRule#health()} or
     * {@link PolicyRule#evaluate(PolicyRequest)}, and it does not consume
     * rate-limit state. Provider-supplied rules therefore cannot narrow
     * selection; the authoritative {@link #evaluate(PolicyRequest)} call still
     * applies them.</p>
     *
     * <p>Every local rule implementing {@link AlgorithmPolicy} contributes
     * hints, merged with strictest-wins semantics. A rule that throws while
     * its hints are collected is skipped: hints are advisory and must never
     * crash selection. The authoritative evaluation of that rule still
     * fails closed later.</p>
     *
     * @param caller caller context; local hints currently do not depend on it
     * @return available hints identified by {@link #engineId()}; when no
     *         algorithm policy exists the returned hints impose no restrictions
     */
    @Override
    public SelectionHints selectionHints(CallerContext caller) {
        SelectionHints merged = null;
        for (PolicyRule rule : rules) {
            if (!(rule instanceof AlgorithmPolicy algorithmPolicy)) {
                continue;
            }
            try {
                merged = SelectionHints.strictest(merged, selectionHintsOf(algorithmPolicy));
            } catch (RuntimeException failure) {
                // Advisory only: skip a broken hint source. evaluate() still
                // fails closed when the authoritative rule is evaluated.
            }
        }
        if (merged == null) {
            return new SelectionHints(engineId, true, Set.of(), false, Set.of(), Map.of(), false);
        }
        return new SelectionHints(engineId, true, merged.allowedAlgorithms(),
                merged.allowListPresent(), merged.deniedAlgorithms(),
                merged.minimumKeyBits(), merged.allowExperimental());
    }

    private SelectionHints selectionHintsOf(AlgorithmPolicy policy) {
        Set<AlgorithmId> allowed = policy.allowedAlgorithms();
        boolean allowListPresent = allowed != null && !allowed.isEmpty();
        Set<AlgorithmId> denied = policy.deniedAlgorithms();
        Map<AlgorithmId, Integer> minimums = new LinkedHashMap<>();
        for (AlgorithmInfo info : AlgorithmCatalog.all()) {
            int required = policy.minimumKeyBits(info.id());
            if (required > 0) {
                minimums.put(info.id(), required);
            }
        }
        return new SelectionHints(engineId, true,
                allowListPresent ? allowed : Set.of(),
                allowListPresent,
                denied == null ? Set.of() : denied,
                minimums,
                policy.allowExperimental());
    }

    @Override
    public PolicyDecision evaluate(PolicyRequest request) {
        try {
            if (request == null) {
                return unavailable(engineId, "No policy request available");
            }
            List<PolicyRule> activeRules = new ArrayList<>(rules);
            for (PolicyProvider provider : providers) {
                String providerId = providerId(provider);
                try {
                    if (failedProviderRefreshes.contains(providerId)) {
                        // A provider whose last refresh failed may be serving
                        // stale rules; deny until a successful refresh clears it.
                        return unavailable(providerId, "Policy provider refresh failed");
                    }
                    HealthStatus status = provider.health();
                    if (status == null || status == HealthStatus.DOWN) {
                        return unavailable(providerId, "Policy provider is unavailable");
                    }
                    PolicySnapshot snapshot = provider.load();
                    if (snapshot == null) {
                        failedProviderRefreshes.add(providerId);
                        return unavailable(providerId, "Policy provider returned no snapshot");
                    }
                    for (PolicyRule providerRule : snapshot.rules()) {
                        if (providerRule == null) {
                            return unavailable(providerId, "Policy provider returned an invalid rule");
                        }
                        activeRules.add(providerRule);
                    }
                } catch (Exception failure) {
                    failedProviderRefreshes.add(providerId);
                    return unavailable(providerId, "Policy provider failed");
                }
            }
            for (PolicyRule rule : activeRules) {
                String ruleId = ruleId(rule);
                try {
                    HealthStatus status = rule.health();
                    if (status == null || status == HealthStatus.DOWN) {
                        return unavailable(ruleId, "Policy rule is unavailable");
                    }
                } catch (Exception failure) {
                    return unavailable(ruleId, "Policy rule health check failed");
                }
            }
            PolicyDecision merged = null;
            for (PolicyRule rule : activeRules) {
                String ruleId = ruleId(rule);
                PolicyDecision decision;
                try {
                    decision = rule.evaluate(request);
                } catch (Exception failure) {
                    return unavailable(ruleId, "Policy rule evaluation failed");
                }
                if (decision == null) {
                    decision = unavailable(ruleId, "Policy rule returned no decision");
                }
                merged = PolicyDecision.strictest(merged, decision);
            }
            // With no decisions strictest(null, null) fails closed.
            return PolicyDecision.strictest(merged, null);
        } catch (Exception failure) {
            return unavailable(engineId, "Policy evaluation is unavailable");
        }
    }

    @Override
    public HealthStatus health() {
        HealthStatus result = HealthStatus.UP;
        for (PolicyRule rule : rules) {
            result = worst(result, ruleHealth(rule));
        }
        for (PolicyProvider provider : providers) {
            result = worst(result, providerHealth(provider));
        }
        return result;
    }

    @Override
    public void refresh() {
        for (PolicyProvider provider : providers) {
            String providerId = providerId(provider);
            try {
                provider.refresh();
                failedProviderRefreshes.remove(providerId);
            } catch (Exception failure) {
                failedProviderRefreshes.add(providerId);
            }
        }
    }

    private HealthStatus ruleHealth(PolicyRule rule) {
        try {
            HealthStatus status = rule.health();
            return status == null ? HealthStatus.DOWN : status;
        } catch (Exception failure) {
            return HealthStatus.DOWN;
        }
    }

    private HealthStatus providerHealth(PolicyProvider provider) {
        try {
            String providerId = providerId(provider);
            if (failedProviderRefreshes.contains(providerId)) {
                return HealthStatus.DOWN;
            }
            HealthStatus status = provider.health();
            return status == null ? HealthStatus.DOWN : status;
        } catch (Exception failure) {
            return HealthStatus.DOWN;
        }
    }

    private static HealthStatus worst(HealthStatus left, HealthStatus right) {
        return severity(left) >= severity(right) ? left : right;
    }

    private static int severity(HealthStatus status) {
        return switch (status) {
            case UP -> 0;
            case DEGRADED -> 1;
            case DOWN -> 2;
        };
    }

    private static PolicyDecision unavailable(String policyId, String message) {
        return PolicyDecision.deny(ReasonCodes.POLICY_UNAVAILABLE, message, policyId);
    }

    private static String ruleId(PolicyRule rule) {
        try {
            String id = rule.ruleId();
            return id == null || id.isBlank() ? FALLBACK_RULE_ID : id;
        } catch (Exception failure) {
            return FALLBACK_RULE_ID;
        }
    }

    private static String providerId(PolicyProvider provider) {
        try {
            String id = provider.providerId();
            return id == null || id.isBlank() ? FALLBACK_PROVIDER_ID : id;
        } catch (Exception failure) {
            return FALLBACK_PROVIDER_ID;
        }
    }

    private static List<PolicyRule> copyRules(List<PolicyRule> source) {
        if (source == null || source.isEmpty()) {
            return List.of();
        }
        List<PolicyRule> copy = new ArrayList<>(source.size());
        for (PolicyRule rule : source) {
            copy.add(Objects.requireNonNull(rule, "rule"));
        }
        return copy;
    }

    private static List<PolicyProvider> copyProviders(List<PolicyProvider> source) {
        if (source == null || source.isEmpty()) {
            return List.of();
        }
        List<PolicyProvider> copy = new ArrayList<>(source.size());
        for (PolicyProvider provider : source) {
            copy.add(Objects.requireNonNull(provider, "provider"));
        }
        return copy;
    }
}