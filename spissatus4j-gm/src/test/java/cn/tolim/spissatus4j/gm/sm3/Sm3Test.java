package cn.tolim.spissatus4j.gm.sm3;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.gm.vector.GmTestVectors;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Sm3Test {

    private final Sm3Hash hash = new Sm3Hash();

    @Test
    void abcKnownAnswerVector() {
        byte[] digest = hash.digest("abc".getBytes(StandardCharsets.US_ASCII));
        assertEquals(GmTestVectors.SM3_ABC_DIGEST, HexFormat.of().formatHex(digest));
    }

    @Test
    void abcdRepeatedSixteenTimesKnownAnswerVector() {
        byte[] digest = hash.digest("abcd".repeat(16).getBytes(StandardCharsets.US_ASCII));
        assertEquals("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
                HexFormat.of().formatHex(digest));
    }

    @Test
    void digestLengthIs256Bits() {
        assertEquals(32, hash.digestLength());
        assertEquals(32, hash.digest(new byte[0]).length);
    }

    @Test
    void algorithmIsSm3() {
        assertEquals(AlgorithmId.SM3, hash.algorithm());
    }

    @Test
    void streamDigestMatchesByteArrayDigest() throws IOException {
        byte[] data = "streamed SM3 payload 你好".getBytes(StandardCharsets.UTF_8);
        byte[] expected = hash.digest(data);
        byte[] streamed = hash.digest(new ByteArrayInputStream(data));
        assertArrayEquals(expected, streamed);
    }

    @Test
    void emptyInputStreamDigestMatchesEmptyArrayDigest() throws IOException {
        assertArrayEquals(hash.digest(new byte[0]), hash.digest(new ByteArrayInputStream(new byte[0])));
    }

    @Test
    void nullDataIsRejected() {
        CryptoException exception =
                assertThrows(CryptoException.class, () -> hash.digest((byte[]) null));
        assertEquals(ErrorCode.INVALID_PARAMETER, exception.errorCode());
    }

    @Test
    void nullInputStreamIsRejected() {
        CryptoException exception =
                assertThrows(CryptoException.class, () -> hash.digest((java.io.InputStream) null));
        assertEquals(ErrorCode.INVALID_PARAMETER, exception.errorCode());
    }

    @Test
    void digestIsDeterministicAndIndependentOfCallOrder() {
        byte[] first = hash.digest("abc".getBytes(StandardCharsets.US_ASCII));
        byte[] other = hash.digest("other".getBytes(StandardCharsets.US_ASCII));
        byte[] second = hash.digest("abc".getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(first, second);
        assertFalse(Arrays.equals(first, other));
    }
}