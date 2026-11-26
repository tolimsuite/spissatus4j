package cn.tolim.spissatus4j.gm.testsupport;

import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.HexFormat;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.function.Executable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Shared deterministic inputs and assertions for the GM tests. */
public final class GmTestSupport {

    public static final byte[] SM4_KEY =
            HexFormat.of().parseHex("0f0e0d0c0b0a09080706050403020100");
    public static final byte[] HMAC_KEY =
            HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f"
                    + "101112131415161718191a1b1c1d1e1f");
    public static final byte[] NONCE_16 =
            HexFormat.of().parseHex("101112131415161718191a1b1c1d1e1f");
    public static final byte[] NONCE_12 =
            HexFormat.of().parseHex("202122232425262728292a2b");

    private GmTestSupport() {
    }

    public static void ensureBcProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static KeyPair sm2KeyPair() throws GeneralSecurityException {
        return ecKeyPair("sm2p256v1");
    }

    public static KeyPair ecKeyPair(String curveName) throws GeneralSecurityException {
        ensureBcProvider();
        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECGenParameterSpec(curveName));
        return generator.generateKeyPair();
    }

    public static SecretKey secretKey(byte[] raw, String algorithm) {
        return new SecretKeySpec(raw.clone(), algorithm);
    }

    public static SecretKey sm4Key() {
        return secretKey(SM4_KEY, "SM4");
    }

    public static SecretKey hmacKey() {
        return secretKey(HMAC_KEY, "HmacSM3");
    }

    public static String hex(byte[] value) {
        return HexFormat.of().formatHex(value);
    }

    public static void assertAuthenticationFailure(Executable executable) {
        CryptoException exception = assertThrows(CryptoException.class, executable);
        assertEquals(ErrorCode.AUTHENTICATION_FAILED, exception.errorCode());
        assertEquals("Cryptographic authentication failed", exception.getMessage());
        assertNull(exception.getCause());
    }

    public static void assertErrorCode(ErrorCode expected, Executable executable) {
        CryptoException exception = assertThrows(CryptoException.class, executable);
        assertEquals(expected, exception.errorCode());
    }
}