package cn.tolim.spissatus4j.contract.spi;

import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import java.util.List;

/**
 * ServiceLoader module contribution. Modules are discovered from
 * {@code META-INF/services}. Third-party module identifiers require explicit
 * trust in the builder; modules shipped under {@code cn.tolim.spissatus4j.}
 * are trusted by default.
 */
public interface SpissatusModule {

    String moduleId();

    default int order() {
        return 100;
    }

    void contribute(ModuleContext context);

    default SelfCheckReport selfCheck() {
        return SelfCheckReport.of(List.of());
    }

    default void close() {
    }
}