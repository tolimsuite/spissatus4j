package cn.tolim.spissatus4j.contract.runtime;

/** Component that can execute a known-answer or health self-check. */
@FunctionalInterface
public interface SelfCheckable {

    SelfCheckReport selfCheck();
}