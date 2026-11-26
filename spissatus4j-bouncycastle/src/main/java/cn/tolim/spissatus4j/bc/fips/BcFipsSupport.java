package cn.tolim.spissatus4j.bc.fips;

import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.security.Provider;
import java.security.Security;

/**
 * Optional Bouncy Castle FIPS provider support.
 *
 * <p>The {@code bc-fips} artifact is intentionally not a compile dependency;
 * the provider class is detected reflectively and only ever touched when the
 * runtime actually ships it. FIPS mode never silently falls back to the
 * non-FIPS provider: when no FIPS provider can be obtained,
 * {@link #requireFips()} and therefore module startup fails.</p>
 */
public final class BcFipsSupport {

    /** JCA name of the Bouncy Castle FIPS provider. */
    public static final String FIPS_PROVIDER_NAME = "BCFIPS";

    private static final String FIPS_PROVIDER_CLASS =
            "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";

    private BcFipsSupport() {
    }

    /**
     * Returns whether a Bouncy Castle FIPS provider is registered or can be
     * instantiated reflectively from the current class path.
     */
    public static boolean isFipsAvailable() {
        if (Security.getProvider(FIPS_PROVIDER_NAME) != null) {
            return true;
        }
        return fipsProviderClass() != null;
    }

    /** Returns the JCA name used for the FIPS provider. */
    public static String providerName() {
        return FIPS_PROVIDER_NAME;
    }

    /**
     * Returns the registered FIPS provider, registering a reflectively
     * instantiated one when necessary.
     *
     * @throws ConfigurationException with {@link ErrorCode#SELF_CHECK_FAILED}
     *         when no FIPS provider is available
     */
    public static Provider requireFips() {
        Provider registered = Security.getProvider(FIPS_PROVIDER_NAME);
        if (registered != null) {
            return registered;
        }
        Class<?> providerClass = fipsProviderClass();
        if (providerClass == null) {
            throw unavailable();
        }
        try {
            Provider provider = (Provider) providerClass.getDeclaredConstructor().newInstance();
            int position = Security.addProvider(provider);
            if (position == -1) {
                Provider raced = Security.getProvider(FIPS_PROVIDER_NAME);
                if (raced == null) {
                    throw unavailable();
                }
                return raced;
            }
            return provider;
        } catch (ReflectiveOperationException | ClassCastException | LinkageError e) {
            throw unavailable();
        } catch (SecurityException e) {
            throw new ConfigurationException(ErrorCode.SELF_CHECK_FAILED,
                    "FIPS provider could not be registered");
        }
    }

    private static Class<?> fipsProviderClass() {
        ClassLoader loader = BcFipsSupport.class.getClassLoader();
        if (loader == null) {
            loader = ClassLoader.getSystemClassLoader();
        }
        try {
            Class<?> type = Class.forName(FIPS_PROVIDER_CLASS, false, loader);
            return Provider.class.isAssignableFrom(type) ? type : null;
        } catch (ClassNotFoundException | LinkageError e) {
            return null;
        }
    }

    private static ConfigurationException unavailable() {
        return new ConfigurationException(ErrorCode.SELF_CHECK_FAILED,
                "FIPS mode is enabled but no FIPS provider is available");
    }
}