package cn.tolim.spissatus4j.gm.sm4;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher.AeadResult;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.gm.testsupport.GmTestSupport;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Sm4GcmCipherTest {

    private final Sm4GcmCipher cipher = new Sm4GcmCipher();
    private final SecretKey key = GmTestSupport.sm4Key();
    private final Nonce nonce = Nonce.of(GmTestSupport.NONCE_12);
    private final AAD aad = AAD.ofUtf8("spissatus4j-gm-header");
    private final byte[] plaintext = "SM4-GCM payload 载荷".getBytes(StandardCharsets.UTF_8);

    @Test
    void metadataReflectsSm4GcmSizes() {
        assertEquals(AlgorithmId.SM4_GCM, cipher.algorithm());
        assertEquals(12, cipher.nonceLength());
        assertEquals(16, cipher.tagLength());
    }

    @Test
    void roundtripWithAad() {
        AeadResult result = cipher.encrypt(key, plaintext, nonce, aad);
        assertEquals(plaintext.length, result.ciphertext().length);
        assertEquals(16, result.tag().length);
        assertEquals(nonce, result.nonce());
        assertArrayEquals(plaintext, cipher.decrypt(key, nonce, result.ciphertext(), result.tag(), aad));
    }

    @Test
    void emptyPlaintextRoundtrip() {
        AeadResult result = cipher.encrypt(key, new byte[0], nonce, aad);
        assertEquals(0, result.ciphertext().length);
        assertEquals(16, result.tag().length);
        assertArrayEquals(new byte[0],
                cipher.decrypt(key, nonce, result.ciphertext(), result.tag(), aad));
    }

    @Test
    void differentNoncesProduceDifferentCiphertexts() {
        Nonce other = Nonce.of(new byte[12]);
        AeadResult first = cipher.encrypt(key, plaintext, nonce, aad);
        AeadResult second = cipher.encrypt(key, plaintext, other, aad);
        assertNotEquals(GmTestSupport.hex(first.ciphertext()), GmTestSupport.hex(second.ciphertext()));
    }

    @Test
    void tamperedCiphertextFailsAuthentication() {
        AeadResult result = cipher.encrypt(key, plaintext, nonce, aad);
        byte[] tampered = result.ciphertext();
        tampered[0] ^= 0x01;
        GmTestSupport.assertAuthenticationFailure(
                () -> cipher.decrypt(key, nonce, tampered, result.tag(), aad));
    }

    @Test
    void tamperedTagFailsAuthentication() {
        AeadResult result = cipher.encrypt(key, plaintext, nonce, aad);
        byte[] tamperedTag = result.tag();
        tamperedTag[tamperedTag.length - 1] ^= 0x01;
        GmTestSupport.assertAuthenticationFailure(
                () -> cipher.decrypt(key, nonce, result.ciphertext(), tamperedTag, aad));
    }

    @Test
    void aadMismatchFailsAuthentication() {
        AeadResult result = cipher.encrypt(key, plaintext, nonce, aad);
        AAD otherAad = AAD.ofUtf8("different-header");
        GmTestSupport.assertAuthenticationFailure(
                () -> cipher.decrypt(key, nonce, result.ciphertext(), result.tag(), otherAad));
    }

    @Test
    void wrongNonceLengthIsRejectedAsNonceInvalid() {
        AeadResult result = cipher.encrypt(key, plaintext, nonce, aad);
        GmTestSupport.assertErrorCode(ErrorCode.NONCE_INVALID,
                () -> cipher.encrypt(key, plaintext, Nonce.of(new byte[16]), aad));
        GmTestSupport.assertErrorCode(ErrorCode.NONCE_INVALID,
                () -> cipher.encrypt(key, plaintext, Nonce.empty(), aad));
        GmTestSupport.assertErrorCode(ErrorCode.NONCE_INVALID,
                () -> cipher.decrypt(key, Nonce.of(new byte[16]),
                        result.ciphertext(), result.tag(), aad));
    }

    @Test
    void wrongTagLengthFailsAuthenticationGenerically() {
        AeadResult result = cipher.encrypt(key, plaintext, nonce, aad);
        GmTestSupport.assertAuthenticationFailure(
                () -> cipher.decrypt(key, nonce, result.ciphertext(), new byte[15], aad));
    }

    @Test
    void wrongKeyLengthIsRejected() {
        SecretKey shortKey = GmTestSupport.secretKey(new byte[15], "SM4");
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> cipher.encrypt(shortKey, plaintext, nonce, aad));
    }

    @Test
    void authenticationFailureMessageCarriesNoDetail() {
        AeadResult result = cipher.encrypt(key, plaintext, nonce, aad);
        byte[] tamperedTag = result.tag();
        tamperedTag[0] ^= 0x01;
        var exception = org.junit.jupiter.api.Assertions.assertThrows(
                cn.tolim.spissatus4j.contract.exception.CryptoException.class,
                () -> cipher.decrypt(key, nonce, result.ciphertext(), tamperedTag, aad));
        assertEquals("Cryptographic authentication failed", exception.getMessage());
        assertTrue(exception.getCause() == null);
    }
}