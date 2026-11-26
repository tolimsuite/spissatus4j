package cn.tolim.spissatus4j.contract.policy;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Non-authoritative hints used to narrow unified algorithm selection.
 *
 * <p>Hints never authorize an operation. The single policy decision performed
 * by the crypto service remains authoritative; a hint only removes candidates
 * before that decision. Implementations must not expose external policy
 * provider contents here unless they can do so without side effects.</p>
 */
public record SelectionHints(
        String sourceId,
        boolean available,
        Set<AlgorithmId> allowedAlgorithms,
        boolean allowListPresent,
        Set<AlgorithmId> deniedAlgorithms,
        Map<AlgorithmId, Integer> minimumKeyBits,
        boolean allowExperimental) {

    public SelectionHints {
        sourceId = Objects.requireNonNull(sourceId, "sourceId");
        allowedAlgorithms = Set.copyOf(Objects.requireNonNull(allowedAlgorithms, "allowedAlgorithms"));
        deniedAlgorithms = Set.copyOf(Objects.requireNonNull(deniedAlgorithms, "deniedAlgorithms"));
        minimumKeyBits = Map.copyOf(Objects.requireNonNull(minimumKeyBits, "minimumKeyBits"));
        if (!allowListPresent) {
            allowedAlgorithms = Set.of();
        }
        for (Map.Entry<AlgorithmId, Integer> entry : minimumKeyBits.entrySet()) {
            Objects.requireNonNull(entry.getKey(), "algorithm");
            if (entry.getValue() == null || entry.getValue() < 0) {
                throw new IllegalArgumentException("minimumKeyBits must not be negative");
            }
        }
    }

    public static SelectionHints none() {
        return new SelectionHints("none", false, Set.of(), false, Set.of(), Map.of(), false);
    }

    /** Combines two hint sets with strictest-wins semantics. */
    public static SelectionHints strictest(SelectionHints left, SelectionHints right) {
        if (left == null) {
            return right == null ? none() : right;
        }
        if (right == null) {
            return left;
        }
        boolean available = left.available || right.available;
        if (!available) {
            return none();
        }
        boolean allowListPresent = left.allowListPresent || right.allowListPresent;
        Set<AlgorithmId> allowed;
        if (left.allowListPresent && right.allowListPresent) {
            Set<AlgorithmId> intersection = new LinkedHashSet<>(left.allowedAlgorithms);
            intersection.retainAll(right.allowedAlgorithms);
            allowed = Set.copyOf(intersection);
        } else if (left.allowListPresent) {
            allowed = left.allowedAlgorithms;
        } else if (right.allowListPresent) {
            allowed = right.allowedAlgorithms;
        } else {
            allowed = Set.of();
        }
        Set<AlgorithmId> denied = new LinkedHashSet<>(left.deniedAlgorithms);
        denied.addAll(right.deniedAlgorithms);
        Map<AlgorithmId, Integer> minimums = new LinkedHashMap<>(left.minimumKeyBits);
        for (Map.Entry<AlgorithmId, Integer> entry : right.minimumKeyBits.entrySet()) {
            minimums.merge(entry.getKey(), entry.getValue(), Math::max);
        }
        return new SelectionHints(left.sourceId + "+" + right.sourceId, true,
                Set.copyOf(allowed), allowListPresent, Set.copyOf(denied),
                Map.copyOf(minimums), left.allowExperimental && right.allowExperimental);
    }

    public boolean permits(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        if (!available) {
            return true;
        }
        if (allowListPresent && !allowedAlgorithms.contains(algorithm)) {
            return false;
        }
        return !deniedAlgorithms.contains(algorithm);
    }

    public int minimumKeyBits(AlgorithmId algorithm) {
        Integer value = minimumKeyBits.get(algorithm);
        return value == null ? 0 : value;
    }
}