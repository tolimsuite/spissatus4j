package cn.tolim.spissatus4j.key;

import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import cn.tolim.spissatus4j.key.manager.KeyManagerFactoryImpl;
import java.util.Objects;

/**
 * Service-loaded contribution of the key module.
 *
 * <p>Contribution is idempotent and side-effect-free apart from registering
 * the default key manager factory. The factory itself reads settings and
 * constructs the configured provider on demand.</p>
 */
public final class KeyModule implements SpissatusModule {

    public static final String MODULE_ID = "key";

    private static final KeyManagerFactoryImpl FACTORY = new KeyManagerFactoryImpl();

    @Override
    public String moduleId() {
        return MODULE_ID;
    }

    @Override
    public int order() {
        return 200;
    }

    @Override
    public void contribute(ModuleContext context) {
        Objects.requireNonNull(context, "context");
        context.registerKeyManagerFactory(FACTORY);
    }
}