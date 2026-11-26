package cn.tolim.spissatus4j.crypto;

import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import cn.tolim.spissatus4j.crypto.internal.JcaAlgorithmProvider;
import cn.tolim.spissatus4j.crypto.random.SecureRandomService;
import cn.tolim.spissatus4j.crypto.stream.AeadStreamCipherService;
import java.util.Locale;
import java.util.Objects;

/**
 * Crypto module contribution: the JCA algorithm provider, the secure random
 * service and the canonical AEAD stream cipher service.
 *
 * <p>Settings (all default to {@code true} when absent):
 * <ul>
 *   <li>{@code spissatus.crypto.jca.enabled}</li>
 *   <li>{@code spissatus.crypto.stream.enabled}</li>
 * </ul>
 */
public final class CryptoModule implements SpissatusModule {

    public static final String MODULE_ID = "crypto";
    public static final int ORDER = 100;

    public static final String SETTING_JCA_ENABLED = "spissatus.crypto.jca.enabled";
    public static final String SETTING_STREAM_ENABLED = "spissatus.crypto.stream.enabled";

    private boolean contributed;
    private volatile JcaAlgorithmProvider provider;

    @Override
    public String moduleId() {
        return MODULE_ID;
    }

    @Override
    public int order() {
        return ORDER;
    }

    @Override
    public synchronized void contribute(ModuleContext context) {
        Objects.requireNonNull(context, "context");
        if (contributed) {
            return;
        }
        boolean jcaEnabled = enabled(context.setting(SETTING_JCA_ENABLED));
        boolean streamEnabled = enabled(context.setting(SETTING_STREAM_ENABLED));
        if (jcaEnabled) {
            JcaAlgorithmProvider instance = new JcaAlgorithmProvider();
            context.registerAlgorithmProvider(instance);
            provider = instance;
        }
        context.registerRandomService(new SecureRandomService());
        if (streamEnabled) {
            context.registerStreamCipherService(new AeadStreamCipherService());
        }
        contributed = true;
    }

    @Override
    public SelfCheckReport selfCheck() {
        JcaAlgorithmProvider instance = provider;
        if (instance == null) {
            instance = new JcaAlgorithmProvider();
        }
        return instance.selfCheck().withPrefix(MODULE_ID);
    }

    private static boolean enabled(java.util.Optional<String> setting) {
        return setting.map(value -> !"false".equals(value.trim().toLowerCase(Locale.ROOT)))
                .orElse(true);
    }
}
