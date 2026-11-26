package cn.tolim.spissatus4j.bc.internal;

import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.HexFormat;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Internal helpers shared by the Bouncy Castle engines.
 *
 * <p>This class is not part of the public API.</p>
 */
public final class BcProviders {

    /** Name of the standard Bouncy Castle JCA provider. */
    public static final String BC_PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

    private static final HexFormat HEX = HexFormat.of();

    private BcProviders() {
    }

    /**
     * Resolves the JCA provider to use: the globally registered {@code BC}
     * provider when present, otherwise a fresh unregistered provider instance.
     * Never mutates the global JCA registry.
     */
    public static Provider resolveProvider() {
        Provider registered = Security.getProvider(BC_PROVIDER_NAME);
        return registered != null ? registered : new BouncyCastleProvider();
    }

    /** Creates an invalid-parameter crypto failure without leaking values. */
    public static CryptoException invalidParameter(String message) {
        return new CryptoException(ErrorCode.INVALID_PARAMETER, message);
    }

    /** Creates a provider-failure crypto failure without leaking values. */
    public static CryptoException providerFailure(String message) {
        return new CryptoException(ErrorCode.PROVIDER_FAILURE, message);
    }

    public static String toHex(byte[] data) {
        return HEX.formatHex(data);
    }

    public static byte[] fromHex(String hex) {
        return HEX.parseHex(hex);
    }

    /** Zeroises a byte array; {@code null} is ignored. */
    public static void clear(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /** Zeroises a char array; {@code null} is ignored. */
    public static void clear(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\0');
        }
    }
}