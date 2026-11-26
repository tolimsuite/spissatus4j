package cn.tolim.spissatus4j.contract.policy;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/** Immutable set of rules loaded from one policy source. */
public record PolicySnapshot(int version, List<PolicyRule> rules, Instant loadedAt) {

    public PolicySnapshot {
        if (version < 0) {
            throw new IllegalArgumentException("version must not be negative");
        }
        rules = List.copyOf(Objects.requireNonNull(rules, "rules"));
        Objects.requireNonNull(loadedAt, "loadedAt");
    }
}