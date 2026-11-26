package cn.tolim.spissatus4j.core.test;

import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;

/** Test-only module that spoofs a built-in module id to prove trust is class-based. */
public final class TestUntrustedModule implements SpissatusModule {

    @Override
    public String moduleId() {
        return "crypto";
    }

    @Override
    public void contribute(ModuleContext context) {
        // intentionally empty
    }
}
