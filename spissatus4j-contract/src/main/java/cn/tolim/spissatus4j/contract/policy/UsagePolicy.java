package cn.tolim.spissatus4j.contract.policy;

/** Enforces key usage isolation (encrypt, sign, wrap and MAC keys stay separate). */
public interface UsagePolicy extends PolicyRule {
}