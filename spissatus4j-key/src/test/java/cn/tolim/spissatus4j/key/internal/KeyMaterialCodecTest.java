package cn.tolim.spissatus4j.key.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.key.internal.KeyMaterialCodec.KeyPairParts;
import cn.tolim.spissatus4j.key.internal.KeyMaterialCodec.PemBlock;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class KeyMaterialCodecTest {

    @Test
    void roundTripsLengthPrefixedKeyPairs() {
        byte[] privateDer = {0x30, 0x01, 0x02};
        byte[] publicDer = {0x30, 0x03, 0x04, 0x05};
        byte[] encoded = KeyMaterialCodec.encodeKeyPair(privateDer, publicDer);

        assertEquals(4 + privateDer.length + 4 + publicDer.length, encoded.length);
        KeyPairParts parts = KeyMaterialCodec.decodeKeyPair(encoded);
        assertArrayEquals(privateDer, parts.privateDer());
        assertArrayEquals(publicDer, parts.publicDer());
    }

    @Test
    void rejectsMalformedKeyPairs() {
        KeyException truncated = assertThrows(KeyException.class,
                () -> KeyMaterialCodec.decodeKeyPair(new byte[]{0, 0, 0, 3, 1, 2}));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, truncated.errorCode());

        KeyException empty = assertThrows(KeyException.class,
                () -> KeyMaterialCodec.decodeKeyPair(new byte[0]));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, empty.errorCode());

        byte[] valid = KeyMaterialCodec.encodeKeyPair(new byte[]{1, 2}, new byte[]{3});
        byte[] extra = Arrays.copyOf(valid, valid.length + 1);
        KeyException lengthMismatch = assertThrows(KeyException.class,
                () -> KeyMaterialCodec.decodeKeyPair(extra));
        assertEquals(ErrorCode.KEY_PROVIDER_FAILURE, lengthMismatch.errorCode());

        assertThrows(KeyException.class,
                () -> KeyMaterialCodec.encodeKeyPair(new byte[0], new byte[]{1}));
    }

    @Test
    void parsesFirstPemBlock() {
        byte[] der = {0x30, 0x06, 0x07, 0x08};
        String pem = "ignored preamble\n"
                + "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(4, new byte[]{'\n'}).encodeToString(der)
                + "\n-----END PRIVATE KEY-----\n"
                + "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n";
        PemBlock block = KeyMaterialCodec.pemBlock(pem.getBytes(StandardCharsets.UTF_8));
        assertEquals("PRIVATE KEY", block.label());
        assertArrayEquals(der, block.der());

        String publicOnly = "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----";
        PemBlock publicBlock = KeyMaterialCodec.pemBlock(
                publicOnly.getBytes(StandardCharsets.UTF_8));
        assertEquals("PUBLIC KEY", publicBlock.label());
        assertArrayEquals(new byte[]{1, 2, 3}, publicBlock.der());
    }

    @Test
    void rejectsInvalidPemWithoutLeakingContent() {
        KeyException missing = assertThrows(KeyException.class,
                () -> KeyMaterialCodec.pemBlock("not a pem".getBytes(StandardCharsets.UTF_8)));
        assertEquals(ErrorCode.KEY_IMPORT_FAILED, missing.errorCode());

        KeyException badBase64 = assertThrows(KeyException.class,
                () -> KeyMaterialCodec.pemBlock(("-----BEGIN PRIVATE KEY-----\n%%%\n"
                        + "-----END PRIVATE KEY-----").getBytes(StandardCharsets.UTF_8)));
        assertEquals(ErrorCode.KEY_IMPORT_FAILED, badBase64.errorCode());
        assertEquals("Invalid PEM encoding", badBase64.getMessage());

        assertTrue(KeyMaterialCodec.isKnownMaterialFormat(KeyMaterialCodec.KEYPAIR));
        assertTrue(KeyMaterialCodec.isKnownMaterialFormat(KeyMaterialCodec.X509));
        assertFalse(KeyMaterialCodec.isKnownMaterialFormat("PEM"));
    }
}