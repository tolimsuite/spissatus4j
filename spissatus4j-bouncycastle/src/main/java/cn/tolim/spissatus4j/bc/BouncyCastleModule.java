package cn.tolim.spissatus4j.bc;

import cn.tolim.spissatus4j.bc.fips.BcFipsSupport;
import cn.tolim.spissatus4j.bc.provider.BouncyCastleAlgorithmProvider;
import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.runtime.SelfCheckReport;
import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Bouncy Castle module: registers the Bouncy Castle algorithm provider and,
 * outside FIPS mode, the standard {@code BC} JCA provider.
 *
 * <p>Settings:</p>
 * <ul>
 *   <li>{@value #SETTING_ENABLED} (default {@code true}) &mdash; when false the
 *       module contributes nothing and touches no global state.</li>
 *   <li>{@value #SETTING_FIPS_ENABLED} (default {@code false}) &mdash; when true
 *       a Bouncy Castle FIPS provider must be available, otherwise startup
 *       fails with {@link ErrorCode#SELF_CHECK_FAILED}. The non-FIPS provider
 *       is never registered or used as a fallback.</li>
 * </ul>
 */
public final class BouncyCastleModule implements SpissatusModule {

    /** Stable module identifier. */
    public static final String MODULE_ID = "bouncycastle";

    /** Module order; runs after the core engines. */
    public static final int ORDER = 250;

    /** Enables or disables this module. */
    public static final String SETTING_ENABLED = "spissatus.provider.bouncycastle.enabled";

    /** Enables FIPS-only operation. */
    public static final String SETTING_FIPS_ENABLED = "spissatus.fips.enabled";

    private volatile BouncyCastleAlgorithmProvider provider;

    @Override
    public String moduleId() {
        return MODULE_ID;
    }

    @Override
    public int order() {
        return ORDER;
    }

    @Override
    public void contribute(ModuleContext context) {
        Objects.requireNonNull(context, "context");
        if (!booleanSetting(context, SETTING_ENABLED, true)) {
            return;
        }
        boolean fips = booleanSetting(context, SETTING_FIPS_ENABLED, false);
        Provider jcaProvider = fips ? BcFipsSupport.requireFips() : registerBcProvider();
        if (fips) {
            context.attribute("spissatus.fips.active", "true");
        }
        BouncyCastleAlgorithmProvider contribution =
                new BouncyCastleAlgorithmProvider(jcaProvider, fips);
        provider = contribution;
        context.registerAlgorithmProvider(contribution);
    }

    @Override
    public SelfCheckReport selfCheck() {
        BouncyCastleAlgorithmProvider current = provider;
        if (current == null) {
            return SelfCheckReport.of(List.of());
        }
        return current.selfCheck().withPrefix("module.bouncycastle");
    }

    @Override
    public void close() {
        BouncyCastleAlgorithmProvider current = provider;
        provider = null;
        if (current != null) {
            current.close();
        }
    }

    private static Provider registerBcProvider() {
        Provider registered = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (registered != null) {
            return registered;
        }
        try {
            BouncyCastleProvider bc = new BouncyCastleProvider();
            Security.addProvider(bc);
            Provider afterRegistration = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
            return afterRegistration != null ? afterRegistration : bc;
        } catch (SecurityException e) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Unable to register the Bouncy Castle JCA provider");
        }
    }

    private static boolean booleanSetting(ModuleContext context, String key, boolean defaultValue) {
        Optional<String> value = context.setting(key);
        if (value == null || value.isEmpty()) {
            return defaultValue;
        }
        String normalized = value.get().trim();
        if ("true".equalsIgnoreCase(normalized)) {
            return true;
        }
        if ("false".equalsIgnoreCase(normalized)) {
            return false;
        }
        throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                "Invalid boolean setting: " + key);
    }
}