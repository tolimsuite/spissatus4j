package cn.tolim.spissatus4j.gm.sm4;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher.AeadResult;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.gm.internal.Sm4Etm;
import cn.tolim.spissatus4j.gm.testsupport.GmTestSupport;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class Sm4EtmCipherTest {

    private final Sm4CbcCipher cbc = new Sm4CbcCipher();
    private final Sm4CtrCipher ctr = new Sm4CtrCipher();
    private final SecretKey key = GmTestSupport.sm4Key();
    private final Nonce nonce = Nonce.of(GmTestSupport.NONCE_16);
    private final AAD aad = AAD.ofUtf8("etm-aad");

    @Test
    void metadataReflectsEtmSizes() {
        assertEquals(AlgorithmId.SM4_CBC, cbc.algorithm());
        assertEquals(AlgorithmId.SM4_CTR, ctr.algorithm());
        assertEquals(16, cbc.nonceLength());
        assertEquals(16, ctr.nonceLength());
        assertEquals(32, cbc.tagLength());
        assertEquals(32, ctr.tagLength());
    }

    @Test
    void cbcRoundtripWithPaddingAndAad() {
        byte[] plaintext = "SM4-CBC payload with padding 填充".getBytes(StandardCharsets.UTF_8);
        AeadResult result = cbc.encrypt(key, plaintext, nonce, aad);
        assertEquals(0, result.ciphertext().length % 16);
        assertEquals(32, result.tag().length);
        assertArrayEquals(plaintext,
                cbc.decrypt(key, nonce, result.ciphertext(), result.tag(), aad));
    }

    @Test
    void cbcEmptyPlaintextRoundtrip() {
        AeadResult result = cbc.encrypt(key, new byte[0], nonce, aad);
        assertEquals(16, result.ciphertext().length);
        assertArrayEquals(new byte[0],
                cbc.decrypt(key, nonce, result.ciphertext(), result.tag(), aad));
    }

    @Test
    void ctrRoundtripWithNonBlockAlignedLength() {
        byte[] plaintext = "SM4-CTR stream payload that is not block aligned".getBytes(StandardCharsets.UTF_8);
        AeadResult result = ctr.encrypt(key, plaintext, nonce, aad);
        assertEquals(plaintext.length, result.ciphertext().length);
        assertEquals(32, result.tag().length);
        assertArrayEquals(plaintext,
                ctr.decrypt(key, nonce, result.ciphertext(), result.tag(), aad));
    }

    @Test
    void ctrEmptyPlaintextRoundtrip() {
        AeadResult result = ctr.encrypt(key, new byte[0], nonce, aad);
        assertEquals(0, result.ciphertext().length);
        assertArrayEquals(new byte[0],
                ctr.decrypt(key, nonce, result.ciphertext(), result.tag(), aad));
    }

    @Test
    void tamperedCiphertextIsRejectedBeforeDecryption() {
        AeadResult cbcResult = cbc.encrypt(key, "cbc data".getBytes(StandardCharsets.US_ASCII), nonce, aad);
        byte[] tamperedCbc = cbcResult.ciphertext();
        tamperedCbc[0] ^= 0x01;
        GmTestSupport.assertAuthenticationFailure(
                () -> cbc.decrypt(key, nonce, tamperedCbc, cbcResult.tag(), aad));

        AeadResult ctrResult = ctr.encrypt(key, "ctr data".getBytes(StandardCharsets.US_ASCII), nonce, aad);
        byte[] tamperedCtr = ctrResult.ciphertext();
        tamperedCtr[0] ^= 0x01;
        GmTestSupport.assertAuthenticationFailure(
                () -> ctr.decrypt(key, nonce, tamperedCtr, ctrResult.tag(), aad));
    }

    @Test
    void tamperedTagIsRejected() {
        AeadResult result = cbc.encrypt(key, "payload".getBytes(StandardCharsets.US_ASCII), nonce, aad);
        byte[] tag = result.tag();
        tag[0] ^= 0x01;
        GmTestSupport.assertAuthenticationFailure(
                () -> cbc.decrypt(key, nonce, result.ciphertext(), tag, aad));
    }

    @Test
    void aadMismatchIsRejected() {
        AeadResult result = cbc.encrypt(key, "payload".getBytes(StandardCharsets.US_ASCII), nonce, aad);
        GmTestSupport.assertAuthenticationFailure(
                () -> cbc.decrypt(key, nonce, result.ciphertext(), result.tag(),
                        AAD.ofUtf8("other-aad")));
    }

    @Test
    void invalidPaddingWithValidMacIsReportedGenerically() {
        byte[] invalidPaddingCiphertext = new byte[16];
        byte[] forgedTag = Sm4Etm.computeTag(AlgorithmId.SM4_CBC, key,
                nonce.asBytes(), aad.asBytes(), invalidPaddingCiphertext);
        GmTestSupport.assertAuthenticationFailure(
                () -> cbc.decrypt(key, nonce, invalidPaddingCiphertext, forgedTag, aad));
    }

    @Test
    void macIsDomainSeparatedByAlgorithmIdentifier() {
        byte[] plaintext = new byte[32];
        AeadResult ctrResult = ctr.encrypt(key, plaintext, nonce, aad);
        byte[] forgedCbcTag = Sm4Etm.computeTag(AlgorithmId.SM4_CTR, key,
                nonce.asBytes(), aad.asBytes(), ctrResult.ciphertext());
        GmTestSupport.assertAuthenticationFailure(
                () -> cbc.decrypt(key, nonce, ctrResult.ciphertext(), forgedCbcTag, aad));
    }

    @Test
    void wrongNonceLengthIsRejectedAsNonceInvalid() {
        byte[] plaintext = "data".getBytes(StandardCharsets.US_ASCII);
        GmTestSupport.assertErrorCode(ErrorCode.NONCE_INVALID,
                () -> cbc.encrypt(key, plaintext, Nonce.of(new byte[15]), aad));
        GmTestSupport.assertErrorCode(ErrorCode.NONCE_INVALID,
                () -> ctr.encrypt(key, plaintext, Nonce.of(new byte[17]), aad));
        AeadResult result = cbc.encrypt(key, plaintext, nonce, aad);
        GmTestSupport.assertErrorCode(ErrorCode.NONCE_INVALID,
                () -> cbc.decrypt(key, Nonce.of(new byte[15]), result.ciphertext(), result.tag(), aad));
    }

    @Test
    void wrongKeyLengthIsRejected() {
        SecretKey shortKey = GmTestSupport.secretKey(new byte[24], "SM4");
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> cbc.encrypt(shortKey, new byte[8], nonce, aad));
        GmTestSupport.assertErrorCode(ErrorCode.INVALID_PARAMETER,
                () -> ctr.encrypt(shortKey, new byte[8], nonce, aad));
    }

    @Test
    void wrongTagLengthIsRejectedGenerically() {
        AeadResult result = cbc.encrypt(key, new byte[8], nonce, aad);
        GmTestSupport.assertAuthenticationFailure(
                () -> cbc.decrypt(key, nonce, result.ciphertext(), new byte[16], aad));
    }

    @Test
    void cbcAndCtrProduceIndependentTagsForTheSameInput() {
        byte[] plaintext = new byte[8];
        AeadCipher.AeadResult cbcResult = cbc.encrypt(key, plaintext, nonce, aad);
        AeadCipher.AeadResult ctrResult = ctr.encrypt(key, plaintext, nonce, aad);
        assertEquals(16, cbcResult.ciphertext().length);
        assertEquals(8, ctrResult.ciphertext().length);
        assertFalse(java.util.Arrays.equals(cbcResult.tag(), ctrResult.tag()));
    }
}