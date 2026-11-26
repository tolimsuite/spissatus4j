package cn.tolim.spissatus4j.gm;

import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import cn.tolim.spissatus4j.gm.provider.GmAlgorithmProvider;
import cn.tolim.spissatus4j.gm.sm2.Sm2KeyWrapper;
import java.security.Security;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.WeakHashMap;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * ServiceLoader contribution for Chinese commercial cryptography.
 *
 * <p>Settings:</p>
 * <ul>
 *   <li>{@code spissatus.provider.gm.enabled} (default {@code true}) controls
 *       whether the GM provider and SM2 key wrapper are registered.</li>
 *   <li>{@code spissatus.fips.enabled} (default {@code false}): when true the
 *       non-FIPS Bouncy Castle JCA provider is not installed; the lightweight
 *       GM engines remain available but FIPS policy rejects them.</li>
 * </ul>
 *
 * <p>Contribution is idempotent per context.</p>
 */
public final class GmModule implements SpissatusModule {

    public static final String MODULE_ID = "gm";
    public static final int MODULE_ORDER = 260;

    public static final String SETTING_ENABLED = "spissatus.provider.gm.enabled";
    public static final String SETTING_FIPS_ENABLED = "spissatus.fips.enabled";

    public static final String ATTRIBUTE_ENABLED = "gm.enabled";
    public static final String ATTRIBUTE_BC_PROVIDER = "gm.bc-provider";
    public static final String ATTRIBUTE_BC_PROVIDER_REGISTERED = "registered";
    public static final String ATTRIBUTE_BC_PROVIDER_PRESENT = "present";
    public static final String ATTRIBUTE_BC_PROVIDER_SKIPPED_FIPS = "skipped-fips";

    private static final System.Logger LOGGER = System.getLogger(GmModule.class.getName());

    private final Set<ModuleContext> contributed = Collections.synchronizedSet(
            Collections.newSetFromMap(new WeakHashMap<>()));
    private final GmAlgorithmProvider provider = new GmAlgorithmProvider();
    private final Sm2KeyWrapper keyWrapper = new Sm2KeyWrapper();

    /**
     * True only after this module actually registered its provider and key
     * wrapper. Volatile because {@link #selfCheck()} has no context and may run
     * on a different thread than {@link #contribute(ModuleContext)}.
     */
    private volatile boolean active;

    @Override
    public String moduleId() {
        return MODULE_ID;
    }

    @Override
    public int order() {
        return MODULE_ORDER;
    }

    @Override
    public void contribute(ModuleContext context) {
        Objects.requireNonNull(context, "context");
        if (!contributed.add(context)) {
            return;
        }
        if (!booleanSetting(context, SETTING_ENABLED, true)) {
            context.attribute(ATTRIBUTE_ENABLED, "false");
            return;
        }
        context.attribute(ATTRIBUTE_ENABLED, "true");
        if (booleanSetting(context, SETTING_FIPS_ENABLED, false)) {
            context.attribute(ATTRIBUTE_BC_PROVIDER, ATTRIBUTE_BC_PROVIDER_SKIPPED_FIPS);
            LOGGER.log(System.Logger.Level.WARNING,
                    "GM module skipped Bouncy Castle JCA provider registration because FIPS mode is enabled");
        } else if (ensureBouncyCastleProvider()) {
            context.attribute(ATTRIBUTE_BC_PROVIDER, ATTRIBUTE_BC_PROVIDER_REGISTERED);
        } else {
            context.attribute(ATTRIBUTE_BC_PROVIDER, ATTRIBUTE_BC_PROVIDER_PRESENT);
        }
        context.registerAlgorithmProvider(provider);
        context.registerKeyWrapper(keyWrapper);
        active = true;
        context.attribute("gm.provider-id", provider.providerId());
        context.attribute("gm.wrapper-id", keyWrapper.wrapperId());
    }

    @Override
    public SelfCheckReport selfCheck() {
        if (!active) {
            return SelfCheckReport.of(List.of());
        }
        return provider.selfCheck().withPrefix(MODULE_ID);
    }

    /**
     * Registers the Bouncy Castle JCA provider when absent.
     *
     * @return true when this call installed the provider, false when it was
     *         already registered
     */
    public static boolean ensureBouncyCastleProvider() {
        synchronized (GmModule.class) {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) != null) {
                return false;
            }
            Security.addProvider(new BouncyCastleProvider());
            return true;
        }
    }

    private static boolean booleanSetting(ModuleContext context, String key, boolean defaultValue) {
        return context.setting(key)
                .map(value -> parseBoolean(key, value))
                .orElse(defaultValue);
    }

    private static boolean parseBoolean(String key, String value) {
        return switch (value.trim().toLowerCase(Locale.ROOT)) {
            case "true", "1", "yes", "on" -> true;
            case "false", "0", "no", "off" -> false;
            default -> throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Invalid boolean value for setting " + key);
        };
    }
}