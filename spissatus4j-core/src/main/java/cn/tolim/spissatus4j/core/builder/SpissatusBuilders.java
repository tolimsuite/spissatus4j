package cn.tolim.spissatus4j.core.builder;

import cn.tolim.spissatus4j.contract.facade.SpissatusBuilder;

/** Entry point for the default facade builder. */
public final class SpissatusBuilders {

    private SpissatusBuilders() {
    }

    public static SpissatusBuilder builder() {
        return new DefaultSpissatusBuilder();
    }
}