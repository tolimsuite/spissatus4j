package cn.tolim.spissatus4j.gm.vector;

import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher.AeadResult;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.gm.internal.BcKeyConversion;
import cn.tolim.spissatus4j.gm.internal.Sm4Ecb;
import cn.tolim.spissatus4j.gm.sm2.Sm2Cipher;
import cn.tolim.spissatus4j.gm.sm2.Sm2Signature;
import cn.tolim.spissatus4j.gm.sm3.Sm3Hash;
import cn.tolim.spissatus4j.gm.sm4.Sm4GcmCipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * Published GB/T known-answer vectors and reproducible round-trip checks used
 * by startup self-checks and tests.
 */
public final class GmTestVectors {

    /** SM3("abc"). */
    public static final String SM3_ABC_DIGEST =
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";

    /** SM3("abcd" repeated 16 times). */
    public static final String SM3_ABCD_X16_DIGEST =
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";

    public static final String SM3_ABC_INPUT = "abc";
    public static final String SM3_ABCD_X16_INPUT = "abcdabcdabcdabcdabcdabcdabcdabcd"
            + "abcdabcdabcdabcdabcdabcdabcdabcd";

    /** GM/T 0002 SM4 ECB single-block vector (key equals plaintext). */
    public static final String SM4_ECB_KEY = "0123456789abcdeffedcba9876543210";
    public static final String SM4_ECB_PLAINTEXT = "0123456789abcdeffedcba9876543210";
    public static final String SM4_ECB_CIPHERTEXT = "681edf34d206965e86b3e94f536e4246";

    public static final String SM4_VECTOR_KEY = "0123456789abcdeffedcba9876543210";
    public static final String SM4_GCM_NONCE = "000102030405060708090a0b";
    public static final byte[] SM4_VECTOR_AAD = "spissatus4j-gm-vector".getBytes(StandardCharsets.US_ASCII);
    public static final String SM4_GCM_PLAINTEXT = "SM4-GCM GM/T 0002 round-trip vector";

    private static final HexFormat HEX = HexFormat.of();

    private GmTestVectors() {
    }

    /** Verifies SM3("abc") against the published digest. */
    public static boolean verifySm3Abc() {
        try {
            return Arrays.equals(hexToBytes(SM3_ABC_DIGEST),
                    new Sm3Hash().digest(SM3_ABC_INPUT.getBytes(StandardCharsets.US_ASCII)));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Verifies the GM/T 0002 SM4-ECB vector through the internal block helper. */
    public static boolean verifySm4EcbVector() {
        try {
            byte[] encrypted = Sm4Ecb.encryptBlock(hexToBytes(SM4_ECB_KEY),
                    hexToBytes(SM4_ECB_PLAINTEXT));
            return Arrays.equals(hexToBytes(SM4_ECB_CIPHERTEXT), encrypted);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Verifies an SM4-GCM encrypt/decrypt round trip with AAD. */
    public static boolean verifySm4GcmRoundtrip() {
        try {
            SecretKey key = new SecretKeySpec(hexToBytes(SM4_VECTOR_KEY), "SM4");
            Nonce nonce = Nonce.of(hexToBytes(SM4_GCM_NONCE));
            AAD aad = AAD.of(SM4_VECTOR_AAD);
            byte[] plaintext = SM4_GCM_PLAINTEXT.getBytes(StandardCharsets.US_ASCII);
            Sm4GcmCipher cipher = new Sm4GcmCipher();
            AeadResult result = cipher.encrypt(key, plaintext, nonce, aad);
            if (result.ciphertext().length != plaintext.length
                    || result.tag().length != Sm4GcmCipher.TAG_LENGTH) {
                return false;
            }
            return Arrays.equals(plaintext,
                    cipher.decrypt(key, nonce, result.ciphertext(), result.tag(), aad));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Verifies SM2 signature and encryption round trips through the public API. */
    public static boolean verifySm2Roundtrip() {
        try {
            AsymmetricCipherKeyPair keyPair = BcKeyConversion.generateKeyPair(new SecureRandom());
            PublicKey publicKey = BcKeyConversion.toJcaPublicKey(
                    (ECPublicKeyParameters) keyPair.getPublic());
            PrivateKey privateKey = BcKeyConversion.toJcaPrivateKey(
                    (ECPrivateKeyParameters) keyPair.getPrivate());

            Sm2Signature signature = new Sm2Signature();
            byte[] message = "spissatus4j-sm2-signature-vector"
                    .getBytes(StandardCharsets.US_ASCII);
            byte[] encodedSignature = signature.sign(privateKey, message);
            if (!signature.verify(publicKey, message, encodedSignature)) {
                return false;
            }
            byte[] tamperedSignature = encodedSignature.clone();
            tamperedSignature[tamperedSignature.length - 1] ^= 0x01;
            if (signature.verify(publicKey, message, tamperedSignature)) {
                return false;
            }

            Sm2Cipher cipher = new Sm2Cipher();
            byte[] plaintext = "spissatus4j-sm2-encryption-vector"
                    .getBytes(StandardCharsets.US_ASCII);
            byte[] ciphertext = cipher.encrypt(publicKey, plaintext);
            return Arrays.equals(plaintext, cipher.decrypt(privateKey, ciphertext));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Parses a hex constant; public so tests can reuse the vector layout. */
    public static byte[] hexToBytes(String hex) {
        return HEX.parseHex(hex);
    }

    /** Checks whether a generated key pair can be encoded as JCA keys (helper). */
    public static boolean verifyJcaKeyRoundtrip(KeyPair keyPair) {
        if (keyPair == null) {
            return false;
        }
        try {
            var publicParameters = BcKeyConversion.toPublicKeyParameters(keyPair.getPublic());
            var privateParameters = BcKeyConversion.toPrivateKeyParameters(keyPair.getPrivate());
            return BcKeyConversion.toJcaPublicKey(publicParameters) != null
                    && BcKeyConversion.toJcaPrivateKey(privateParameters) != null;
        } catch (RuntimeException e) {
            return false;
        }
    }
}