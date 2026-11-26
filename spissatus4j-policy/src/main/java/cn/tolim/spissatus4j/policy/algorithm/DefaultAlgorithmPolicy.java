package cn.tolim.spissatus4j.policy.algorithm;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmCatalog;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.algorithm.AlgorithmInfo;
import cn.tolim.spissatus4j.contract.algorithm.Operation;
import cn.tolim.spissatus4j.contract.algorithm.SecurityStatus;
import cn.tolim.spissatus4j.contract.key.KeyDescriptor;
import cn.tolim.spissatus4j.contract.policy.AlgorithmPolicy;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Default algorithm policy: rejects unregistered, prohibited and disallowed
 * algorithms, warns about deprecated ones, gates experimental algorithms behind
 * an explicit opt-in and enforces the catalog minimum key size for operations
 * that carry a key descriptor.
 *
 * <p>The policy never inspects key material; only non-secret metadata is used.
 * Algorithm identifiers are safe to include in decision messages.</p>
 */
public final class DefaultAlgorithmPolicy implements AlgorithmPolicy {

    /** Stable, non-sensitive policy identifier. */
    public static final String RULE_ID = "algorithm";

    private final Set<AlgorithmId> allowedAlgorithms;
    private final Set<AlgorithmId> deniedAlgorithms;
    private final boolean allowExperimental;
    private final Map<AlgorithmId, Integer> minimumKeyBits;

    /**
     * Creates the default policy: every registered algorithm is accepted
     * subject to its catalog lifecycle, experimental algorithms are denied and
     * minimum key sizes come from the catalog.
     */
    public DefaultAlgorithmPolicy() {
        this(Set.of(), Set.of(), false);
    }

    /**
     * Creates a policy without key-size overrides.
     *
     * @param allowedAlgorithms whitelist; when non-empty only these algorithms are allowed
     * @param deniedAlgorithms blacklist; these algorithms are always denied
     * @param allowExperimental whether experimental algorithms may be used
     */
    public DefaultAlgorithmPolicy(Set<AlgorithmId> allowedAlgorithms,
                                  Set<AlgorithmId> deniedAlgorithms,
                                  boolean allowExperimental) {
        this(allowedAlgorithms, deniedAlgorithms, allowExperimental, Map.of());
    }

    /**
     * Creates a fully configured policy.
     *
     * @param allowedAlgorithms whitelist; when non-empty only these algorithms are allowed
     * @param deniedAlgorithms blacklist; these algorithms are always denied
     * @param allowExperimental whether experimental algorithms may be used
     * @param minimumKeyBits per-algorithm minimum key sizes overriding catalog values;
     *                        a value of {@code 0} disables the size check for that algorithm
     * @throws IllegalArgumentException if a minimum key size is negative
     */
    public DefaultAlgorithmPolicy(Set<AlgorithmId> allowedAlgorithms,
                                  Set<AlgorithmId> deniedAlgorithms,
                                  boolean allowExperimental,
                                  Map<AlgorithmId, Integer> minimumKeyBits) {
        this.allowedAlgorithms = copyAlgorithms(allowedAlgorithms);
        this.deniedAlgorithms = copyAlgorithms(deniedAlgorithms);
        this.allowExperimental = allowExperimental;
        this.minimumKeyBits = copyMinimums(minimumKeyBits);
    }

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public Set<AlgorithmId> allowedAlgorithms() {
        return allowedAlgorithms;
    }

    @Override
    public Set<AlgorithmId> deniedAlgorithms() {
        return deniedAlgorithms;
    }

    @Override
    public int minimumKeyBits(AlgorithmId algorithm) {
        if (algorithm == null) {
            return 0;
        }
        Integer override = minimumKeyBits.get(algorithm);
        if (override != null) {
            return override;
        }
        return AlgorithmCatalog.infoOrUnknown(algorithm.id()).minKeyBits();
    }

    @Override
    public PolicyDecision evaluate(PolicyRequest request) {
        if (request == null) {
            return PolicyDecision.deny(ReasonCodes.POLICY_UNAVAILABLE,
                    "No policy request available", RULE_ID);
        }
        if (isLifecycleManagement(request.operation())) {
            // Cleanup/administrative operations must remain possible for keys
            // whose algorithm has since been prohibited or deprecated.
            return PolicyDecision.allow(RULE_ID);
        }
        AlgorithmId algorithm = request.algorithm();
        if (algorithm == null) {
            // No algorithm on the request, but an existing key still carries
            // the algorithm it was created for: enforce the full algorithm
            // policy against that descriptor instead of allowing blindly.
            KeyDescriptor key = request.key();
            algorithm = key == null ? null : key.algorithm();
        }
        if (algorithm == null) {
            // Key-management operations that name neither an algorithm nor a
            // key descriptor are outside the scope of this rule.
            return PolicyDecision.allow(RULE_ID);
        }
        AlgorithmInfo info = AlgorithmCatalog.infoOrUnknown(algorithm.id());
        if (!algorithm.isKnown() || info.status() == SecurityStatus.UNKNOWN) {
            return PolicyDecision.deny(ReasonCodes.ALGORITHM_UNKNOWN,
                    "Algorithm is not registered", RULE_ID);
        }
        if (deniedAlgorithms.contains(algorithm) || info.status() == SecurityStatus.PROHIBITED) {
            return PolicyDecision.deny(ReasonCodes.ALGORITHM_PROHIBITED,
                    "Algorithm " + algorithm.id() + " is prohibited", RULE_ID);
        }
        if (!allowedAlgorithms.isEmpty() && !allowedAlgorithms.contains(algorithm)) {
            return PolicyDecision.deny(ReasonCodes.ALGORITHM_NOT_ALLOWED,
                    "Algorithm " + algorithm.id() + " is not in the allowed algorithm list", RULE_ID);
        }
        if (info.status() == SecurityStatus.EXPERIMENTAL && !allowExperimental) {
            return PolicyDecision.deny(ReasonCodes.ALGORITHM_EXPERIMENTAL,
                    "Algorithm " + algorithm.id() + " is experimental", RULE_ID);
        }
        if (info.status() == SecurityStatus.DEPRECATED) {
            PolicyDecision warning = PolicyDecision.warn(ReasonCodes.ALGORITHM_DEPRECATED,
                    "Algorithm " + algorithm.id() + " is deprecated", RULE_ID);
            PolicyDecision sizeDecision = checkKeySize(request, algorithm);
            return PolicyDecision.strictest(warning, sizeDecision);
        }
        return checkKeySize(request, algorithm);
    }

    private static boolean isLifecycleManagement(Operation operation) {
        return operation == Operation.DESTROY_KEY || operation == Operation.REVOKE_KEY
                || operation == Operation.COMPROMISE_KEY || operation == Operation.DEACTIVATE_KEY
                || operation == Operation.READ_KEY;
    }

    private PolicyDecision checkKeySize(PolicyRequest request, AlgorithmId algorithm) {
        KeyDescriptor key = request.key();
        if (key == null) {
            // A key-generation request has no descriptor yet; the catalog
            // minimum is enforced by the generator, not by this rule.
            return PolicyDecision.allow(RULE_ID);
        }
        int required = minimumKeyBits(algorithm);
        if (required > 0 && key.keyBits() < required) {
            return PolicyDecision.deny(ReasonCodes.MIN_KEY_BITS,
                    "Key size is below the minimum for " + algorithm.id(), RULE_ID,
                    Map.of("requiredBits", Integer.toString(required),
                            "actualBits", Integer.toString(key.keyBits())));
        }
        return PolicyDecision.allow(RULE_ID);
    }

    private static Set<AlgorithmId> copyAlgorithms(Set<AlgorithmId> source) {
        if (source == null || source.isEmpty()) {
            return Set.of();
        }
        LinkedHashSet<AlgorithmId> copy = new LinkedHashSet<>();
        for (AlgorithmId algorithm : source) {
            copy.add(Objects.requireNonNull(algorithm, "algorithm"));
        }
        return Set.copyOf(copy);
    }

    private static Map<AlgorithmId, Integer> copyMinimums(Map<AlgorithmId, Integer> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }
        LinkedHashMap<AlgorithmId, Integer> copy = new LinkedHashMap<>();
        for (Map.Entry<AlgorithmId, Integer> entry : source.entrySet()) {
            AlgorithmId algorithm = Objects.requireNonNull(entry.getKey(), "algorithm");
            Integer bits = Objects.requireNonNull(entry.getValue(), "minimumKeyBits");
            if (bits < 0) {
                throw new IllegalArgumentException("minimumKeyBits must not be negative");
            }
            copy.put(algorithm, bits);
        }
        return Map.copyOf(copy);
    }
}