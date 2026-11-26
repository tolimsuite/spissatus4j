package cn.tolim.spissatus4j.crypto.stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.StreamHeader;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import cn.tolim.spissatus4j.crypto.TestSupport;
import cn.tolim.spissatus4j.crypto.internal.JcaAlgorithmProvider;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class AeadStreamCipherServiceTest {

    private static final JcaAlgorithmProvider PROVIDER = new JcaAlgorithmProvider();
    private static final AeadStreamCipherService SERVICE = new AeadStreamCipherService();
    private static final SecretKey KEY = new SecretKeySpec(TestSupport.bytes(32, 500), "AES");
    private static final int CHUNK_SIZE = 1024;
    private static final int GCM_FRAME_SIZE = 4 + CHUNK_SIZE + 16;

    @BeforeAll
    static void checkFormatId() {
        assertEquals("SPISSATUS-AEAD-STREAM-1", SERVICE.formatId());
    }

    @Test
    void multiChunkRoundtripWithMoreThanThreeChunks() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.ofUtf8("user-aad"));
        byte[] plaintext = TestSupport.bytes(5000, 1);
        byte[] stream = encrypt(header, KEY, plaintext);

        int headerLength = headerLength(header);
        assertEquals(headerLength + 4 * GCM_FRAME_SIZE + (4 + 904 + 16), stream.length);

        StreamHeader readHeader = readHeader(stream);
        assertEquals(header, readHeader);
        assertArrayEquals(plaintext, decrypt(stream, KEY));
    }

    @Test
    void emptyInputWritesOneFinalEmptyChunk() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.empty());
        byte[] stream = encrypt(header, KEY, new byte[0]);
        assertEquals(headerLength(header) + 4 + 16, stream.length);
        assertArrayEquals(new byte[0], decrypt(stream, KEY));
    }

    @Test
    void writeInIrregularPiecesProducesSamePlaintext() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.ofUtf8("pieces"));
        byte[] plaintext = TestSupport.bytes(3333, 2);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        SERVICE.writeHeader(output, header);
        try (OutputStream encrypting = SERVICE.openEncrypting(output, header,
                PROVIDER.aeadCipher(AlgorithmId.AES_GCM), KEY)) {
            int offset = 0;
            int[] sizes = {1, 17, 1000, 3, 512, 1800};
            int index = 0;
            while (offset < plaintext.length) {
                int size = Math.min(sizes[index++ % sizes.length], plaintext.length - offset);
                encrypting.write(plaintext, offset, size);
                offset += size;
            }
            encrypting.flush();
        }
        assertArrayEquals(plaintext, decrypt(output.toByteArray(), KEY));
    }

    @Test
    void tamperedMiddleChunkIsDetected() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.ofUtf8("tamper"));
        byte[] stream = encrypt(header, KEY, TestSupport.bytes(5000, 3));
        int headerLength = headerLength(header);
        stream[headerLength + 2 * GCM_FRAME_SIZE + 4 + 100] ^= 0x01;

        CryptoException exception = decryptExpectingFailure(stream, KEY);
        assertEquals(ErrorCode.STREAM_CORRUPTED, exception.errorCode());
    }

    @Test
    void truncatedFinalFrameIsDetected() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.empty());
        byte[] stream = encrypt(header, KEY, TestSupport.bytes(5000, 4));
        byte[] truncated = Arrays.copyOf(stream, stream.length - 10);

        CryptoException exception = decryptExpectingFailure(truncated, KEY);
        assertEquals(ErrorCode.STREAM_TRUNCATED, exception.errorCode());
    }

    @Test
    void droppedFinalChunkIsReportedAsTruncation() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.empty());
        byte[] stream = encrypt(header, KEY, TestSupport.bytes(5000, 5));
        int headerLength = headerLength(header);
        byte[] truncated = Arrays.copyOf(stream, headerLength + 4 * GCM_FRAME_SIZE);

        CryptoException exception = decryptExpectingFailure(truncated, KEY);
        assertEquals(ErrorCode.STREAM_TRUNCATED, exception.errorCode());
    }

    @Test
    void reorderedChunksAreRejected() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.empty());
        byte[] stream = encrypt(header, KEY, TestSupport.bytes(5000, 6));
        int headerLength = headerLength(header);
        int first = headerLength + GCM_FRAME_SIZE;
        int second = headerLength + 2 * GCM_FRAME_SIZE;
        byte[] reordered = stream.clone();
        System.arraycopy(stream, second, reordered, first, GCM_FRAME_SIZE);
        System.arraycopy(stream, first, reordered, second, GCM_FRAME_SIZE);

        CryptoException exception = decryptExpectingFailure(reordered, KEY);
        assertTrue(exception.errorCode() == ErrorCode.STREAM_CORRUPTED
                        || exception.errorCode() == ErrorCode.STREAM_ORDER_VIOLATION,
                () -> "unexpected error code " + exception.errorCode());
    }

    @Test
    void finalChunkFollowedByAnotherFrameIsAnOrderViolation() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.empty());
        byte[] stream = encrypt(header, KEY, TestSupport.bytes(5000, 7));
        int headerLength = headerLength(header);
        int extraFrameStart = headerLength + GCM_FRAME_SIZE;
        byte[] withTrailingFrame = TestSupport.concat(stream,
                Arrays.copyOfRange(stream, extraFrameStart, extraFrameStart + GCM_FRAME_SIZE));

        CryptoException exception = decryptExpectingFailure(withTrailingFrame, KEY);
        assertEquals(ErrorCode.STREAM_ORDER_VIOLATION, exception.errorCode());
    }

    @Test
    void skipChunksThenResumeDecryptsSuffix() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.ofUtf8("resume"));
        byte[] plaintext = TestSupport.bytes(5000, 8);
        byte[] stream = encrypt(header, KEY, plaintext);

        ByteArrayInputStream input = new ByteArrayInputStream(stream);
        StreamHeader readHeader = SERVICE.readHeader(input);
        SERVICE.skipChunks(input, readHeader, 2);
        try (InputStream decrypting = SERVICE.openDecrypting(input, readHeader,
                PROVIDER.aeadCipher(AlgorithmId.AES_GCM), KEY, 2)) {
            assertArrayEquals(Arrays.copyOfRange(plaintext, 2 * CHUNK_SIZE, plaintext.length),
                    decrypting.readAllBytes());
        }
    }

    @Test
    void skipChunksPastEndIsTruncation() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.empty());
        byte[] stream = encrypt(header, KEY, TestSupport.bytes(2500, 9));
        ByteArrayInputStream input = new ByteArrayInputStream(stream);
        StreamHeader readHeader = SERVICE.readHeader(input);
        CryptoException exception = assertThrows(CryptoException.class,
                () -> SERVICE.skipChunks(input, readHeader, 10));
        assertEquals(ErrorCode.STREAM_TRUNCATED, exception.errorCode());
    }

    @Test
    void decryptionStreamDoesNotCloseUnderlyingStream() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.empty());
        byte[] stream = encrypt(header, KEY, TestSupport.bytes(2000, 10));

        TrackingInputStream tracking = new TrackingInputStream(stream);
        StreamHeader readHeader = SERVICE.readHeader(tracking);
        InputStream decrypting = SERVICE.openDecrypting(tracking, readHeader,
                PROVIDER.aeadCipher(AlgorithmId.AES_GCM), KEY, 0);
        assertEquals(2000, decrypting.readAllBytes().length);
        decrypting.close();
        assertFalse(tracking.closed);
    }

    @Test
    void encryptionStreamDoesNotCloseUnderlyingStreamAndFlushes() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.ofUtf8("close"));
        TrackingOutputStream tracking = new TrackingOutputStream();
        SERVICE.writeHeader(tracking, header);
        OutputStream encrypting = SERVICE.openEncrypting(tracking, header,
                PROVIDER.aeadCipher(AlgorithmId.AES_GCM), KEY);
        encrypting.write(TestSupport.bytes(3000, 11));
        encrypting.close();
        assertFalse(tracking.closed);
        assertTrue(tracking.flushes > 0);
        assertArrayEquals(TestSupport.bytes(3000, 11), decrypt(tracking.toByteArray(), KEY));
    }

    @Test
    void singleByteReadsWorkAcrossChunks() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.empty());
        byte[] plaintext = TestSupport.bytes(2050, 12);
        byte[] stream = encrypt(header, KEY, plaintext);
        ByteArrayInputStream input = new ByteArrayInputStream(stream);
        StreamHeader readHeader = SERVICE.readHeader(input);
        try (InputStream decrypting = SERVICE.openDecrypting(input, readHeader,
                PROVIDER.aeadCipher(AlgorithmId.AES_GCM), KEY, 0)) {
            ByteArrayOutputStream collected = new ByteArrayOutputStream();
            int value;
            while ((value = decrypting.read()) != -1) {
                collected.write(value);
            }
            assertArrayEquals(plaintext, collected.toByteArray());
        }
    }

    @Test
    void headerOnlyStreamIsTruncated() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.empty());
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        SERVICE.writeHeader(output, header);
        ByteArrayInputStream input = new ByteArrayInputStream(output.toByteArray());
        StreamHeader readHeader = SERVICE.readHeader(input);
        InputStream decrypting = SERVICE.openDecrypting(input, readHeader,
                PROVIDER.aeadCipher(AlgorithmId.AES_GCM), KEY, 0);
        CryptoException exception = assertThrows(CryptoException.class, decrypting::readAllBytes);
        assertEquals(ErrorCode.STREAM_TRUNCATED, exception.errorCode());
    }

    @Test
    void frameLengthAllOnesIsRejectedInsteadOfTreatedAsEof() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.empty());
        byte[] stream = encrypt(header, KEY, TestSupport.bytes(2000, 21));
        ByteArrayInputStream probe = new ByteArrayInputStream(stream);
        StreamHeader parsed = SERVICE.readHeader(probe);
        assertEquals(header, parsed);
        int actualHeaderLength = stream.length - probe.available();
        int frameLengthOffset = headerLength(header);
        assertEquals(actualHeaderLength, frameLengthOffset,
                "header length helper mismatch");
        int originalLength = intAt(stream, frameLengthOffset);
        assertEquals(CHUNK_SIZE + 16, originalLength,
                "frame offset mismatch: " + originalLength);
        stream[frameLengthOffset] = (byte) 0xff;
        stream[frameLengthOffset + 1] = (byte) 0xff;
        stream[frameLengthOffset + 2] = (byte) 0xff;
        stream[frameLengthOffset + 3] = (byte) 0xff;
        InputStream decrypting = SERVICE.openDecrypting(probe,
                header, PROVIDER.aeadCipher(AlgorithmId.AES_GCM), KEY, 0);
        CryptoException failure = assertThrows(CryptoException.class, decrypting::readAllBytes);
        assertEquals(ErrorCode.STREAM_CORRUPTED, failure.errorCode(), failure.getMessage());
    }

    @Test
    void headerAttributesAreCanonicalAndRoundtrip() throws IOException {
        StreamHeader header = new StreamHeader(StreamHeader.CURRENT_VERSION, AlgorithmId.AES_GCM,
                KeyId.of("stream-key"), KeyVersion.of(7), Nonce.of(TestSupport.bytes(12, 13)),
                CHUNK_SIZE, AAD.ofUtf8("aad"), Instant.ofEpochMilli(1_700_000_123_456L),
                Map.of("z", "last", "a", "first", "m", "middle"));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        SERVICE.writeHeader(output, header);
        StreamHeader read = SERVICE.readHeader(new ByteArrayInputStream(output.toByteArray()));
        assertEquals(header, read);
        assertEquals(Set.of("z", "a", "m"), read.attributes().keySet());
    }

    @Test
    void headerValidationRejectsBadMagicVersionAndChunkSize() throws IOException {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.empty());
        byte[] encoded = headerBytes(header);

        byte[] badMagic = encoded.clone();
        badMagic[0] ^= 0x01;
        assertEquals(ErrorCode.STREAM_CORRUPTED, assertThrows(CryptoException.class,
                () -> SERVICE.readHeader(new ByteArrayInputStream(badMagic))).errorCode());

        byte[] badVersion = encoded.clone();
        badVersion[11] = 2;
        assertEquals(ErrorCode.STREAM_CORRUPTED, assertThrows(CryptoException.class,
                () -> SERVICE.readHeader(new ByteArrayInputStream(badVersion))).errorCode());

        byte[] badChunkSize = encoded.clone();
        int chunkSizeOffset = 8 + 4
                + 4 + header.algorithm().id().getBytes(StandardCharsets.UTF_8).length
                + 4 + header.keyId().value().getBytes(StandardCharsets.UTF_8).length
                + 8 + 4 + header.baseNonce().length();
        badChunkSize[chunkSizeOffset] = 0;
        badChunkSize[chunkSizeOffset + 1] = 0;
        badChunkSize[chunkSizeOffset + 2] = 0;
        badChunkSize[chunkSizeOffset + 3] = 16;
        assertEquals(ErrorCode.STREAM_CORRUPTED, assertThrows(CryptoException.class,
                () -> SERVICE.readHeader(new ByteArrayInputStream(badChunkSize))).errorCode());

        byte[] truncatedHeader = Arrays.copyOf(encoded, 10);
        assertEquals(ErrorCode.STREAM_CORRUPTED, assertThrows(CryptoException.class,
                () -> SERVICE.readHeader(new ByteArrayInputStream(truncatedHeader))).errorCode());
    }

    @Test
    void oversizedHeaderIsRejectedOnWrite() {
        StreamHeader header = new StreamHeader(StreamHeader.CURRENT_VERSION, AlgorithmId.AES_GCM,
                KeyId.of("big"), KeyVersion.first(), Nonce.of(TestSupport.bytes(12, 14)),
                CHUNK_SIZE, AAD.of(new byte[1024 * 1024]), Instant.now(), Map.of());
        CryptoException exception = assertThrows(CryptoException.class,
                () -> SERVICE.writeHeader(new ByteArrayOutputStream(), header));
        assertEquals(ErrorCode.STREAM_LIMIT_EXCEEDED, exception.errorCode());
    }

    @Test
    void streamRequiresTwelveByteBaseNonce() throws IOException {
        StreamHeader header = new StreamHeader(StreamHeader.CURRENT_VERSION, AlgorithmId.AES_GCM,
                KeyId.of("nonce"), KeyVersion.first(), Nonce.of(TestSupport.bytes(16, 15)),
                CHUNK_SIZE, AAD.empty(), Instant.now(), Map.of());
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        SERVICE.writeHeader(output, header);
        CryptoException exception = assertThrows(CryptoException.class,
                () -> SERVICE.openEncrypting(output, header,
                        PROVIDER.aeadCipher(AlgorithmId.AES_GCM), KEY));
        assertEquals(ErrorCode.NONCE_INVALID, exception.errorCode());
    }

    @Test
    void chunkNoncesAndAadFollowTheCanonicalDerivation() throws Exception {
        StreamHeader header = header(AlgorithmId.AES_GCM, CHUNK_SIZE, AAD.ofUtf8("derivation"));
        byte[] plaintext = TestSupport.bytes(5000, 18);
        RecordingCipher recording = new RecordingCipher(
                PROVIDER.aeadCipher(AlgorithmId.AES_GCM));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        SERVICE.writeHeader(output, header);
        try (OutputStream encrypting = SERVICE.openEncrypting(output, header, recording, KEY)) {
            encrypting.write(plaintext);
        }

        byte[] baseNonce = header.baseNonce().asBytes();
        byte[] headerHash = MessageDigest.getInstance("SHA-256").digest(headerBytes(header));
        byte[] userAad = header.aad().asBytes();
        int baseTail = ((baseNonce[8] & 0xff) << 24) | ((baseNonce[9] & 0xff) << 16)
                | ((baseNonce[10] & 0xff) << 8) | (baseNonce[11] & 0xff);
        assertEquals(5, recording.nonces.size());
        for (int i = 0; i < recording.nonces.size(); i++) {
            byte[] nonce = recording.nonces.get(i).asBytes();
            assertEquals(12, nonce.length);
            assertArrayEquals(Arrays.copyOf(baseNonce, 8), Arrays.copyOf(nonce, 8),
                    "base nonce prefix changed for chunk " + i);
            // Intentional behavior change from the nonce-collapse fix: every
            // base-nonce byte is preserved and the chunk index is XORed into
            // the trailing four bytes instead of replacing them.
            int tail = ((nonce[8] & 0xff) << 24) | ((nonce[9] & 0xff) << 16)
                    | ((nonce[10] & 0xff) << 8) | (nonce[11] & 0xff);
            assertEquals(baseTail ^ i, tail, "chunk nonce tail mismatch for chunk " + i);
            if (i == 0) {
                assertArrayEquals(baseNonce, nonce, "chunk 0 must reuse the base nonce");
            }

            byte[] aad = recording.aads.get(i).asBytes();
            int userLength = ((aad[0] & 0xff) << 24) | ((aad[1] & 0xff) << 16)
                    | ((aad[2] & 0xff) << 8) | (aad[3] & 0xff);
            assertEquals(userAad.length, userLength);
            assertArrayEquals(userAad, Arrays.copyOfRange(aad, 4, 4 + userLength));
            assertArrayEquals(headerHash,
                    Arrays.copyOfRange(aad, 4 + userLength, 4 + userLength + 32));
            int offset = 4 + userLength + 32;
            long encodedIndex = 0;
            for (int b = 0; b < 8; b++) {
                encodedIndex = (encodedIndex << 8) | (aad[offset + b] & 0xffL);
            }
            assertEquals(i, encodedIndex);
            assertEquals(i == recording.nonces.size() - 1 ? 1 : 0, aad[offset + 8]);
        }
    }

    @Test
    void chunkNoncePreservesAllBaseBytesAndEnforcesTheEncodableRange() {
        byte[] baseBytes = TestSupport.bytes(12, 20);
        Nonce base = Nonce.of(baseBytes);

        assertArrayEquals(baseBytes, AeadStreamCipherService.chunkNonce(base, 0).asBytes(),
                "chunk 0 must reuse the base nonce");

        long index = 0x01020304L;
        byte[] expected = baseBytes.clone();
        expected[8] ^= 0x01;
        expected[9] ^= 0x02;
        expected[10] ^= 0x03;
        expected[11] ^= 0x04;
        assertArrayEquals(expected, AeadStreamCipherService.chunkNonce(base, index).asBytes());

        byte[] last = AeadStreamCipherService.chunkNonce(base, 0xFFFFFFFFL).asBytes();
        assertArrayEquals(Arrays.copyOf(baseBytes, 8), Arrays.copyOf(last, 8),
                "the 0xffffffff chunk must keep the base nonce prefix");

        assertEquals(ErrorCode.STREAM_LIMIT_EXCEEDED, assertThrows(CryptoException.class,
                () -> AeadStreamCipherService.chunkNonce(base, -1)).errorCode());
        assertEquals(ErrorCode.STREAM_LIMIT_EXCEEDED, assertThrows(CryptoException.class,
                () -> AeadStreamCipherService.chunkNonce(base, 0x1_0000_0000L)).errorCode());
        assertEquals(ErrorCode.NONCE_INVALID, assertThrows(CryptoException.class,
                () -> AeadStreamCipherService.chunkNonce(Nonce.of(new byte[16]), 0)).errorCode());
    }

    @Test
    void streamsDifferingOnlyInTrailingBaseNonceBytesProduceDifferentNoncesAndCiphertext()
            throws IOException {
        byte[] baseA = TestSupport.bytes(12, 21);
        byte[] baseB = baseA.clone();
        baseB[8] ^= (byte) 0x80;
        baseB[11] ^= 0x01;
        assertArrayEquals(Arrays.copyOf(baseA, 8), Arrays.copyOf(baseB, 8),
                "the two base nonces must share their leading eight bytes");

        StreamHeader headerA = headerWithNonce(AlgorithmId.AES_GCM, CHUNK_SIZE,
                AAD.ofUtf8("tail"), Nonce.of(baseA));
        StreamHeader headerB = headerWithNonce(AlgorithmId.AES_GCM, CHUNK_SIZE,
                AAD.ofUtf8("tail"), Nonce.of(baseB));
        byte[] plaintext = TestSupport.bytes(3 * CHUNK_SIZE + 17, 22);
        RecordingCipher recordingA = new RecordingCipher(PROVIDER.aeadCipher(AlgorithmId.AES_GCM));
        RecordingCipher recordingB = new RecordingCipher(PROVIDER.aeadCipher(AlgorithmId.AES_GCM));
        byte[] streamA = encrypt(headerA, KEY, plaintext, recordingA);
        byte[] streamB = encrypt(headerB, KEY, plaintext, recordingB);

        assertEquals(4, recordingA.nonces.size());
        assertEquals(recordingA.nonces.size(), recordingB.nonces.size());
        for (int i = 0; i < recordingA.nonces.size(); i++) {
            byte[] nonceA = recordingA.nonces.get(i).asBytes();
            byte[] nonceB = recordingB.nonces.get(i).asBytes();
            assertArrayEquals(Arrays.copyOf(baseA, 8), Arrays.copyOf(nonceA, 8));
            assertArrayEquals(Arrays.copyOf(baseB, 8), Arrays.copyOf(nonceB, 8));
            assertFalse(Arrays.equals(nonceA, nonceB),
                    "chunk " + i + " reused a nonce across streams");
        }

        int headerLength = headerBytes(headerA).length;
        assertEquals(headerLength, headerBytes(headerB).length);
        int payloadLength = intAt(streamA, headerLength);
        assertEquals(payloadLength, intAt(streamB, headerLength));
        assertFalse(Arrays.equals(
                        Arrays.copyOfRange(streamA, headerLength + 4,
                                headerLength + 4 + payloadLength),
                        Arrays.copyOfRange(streamB, headerLength + 4,
                                headerLength + 4 + payloadLength)),
                "the same chunk produced identical ciphertext and tag");
    }

    @Test
    void chunkNoncesAreUniqueAcrossManyChunksAndTwoStreams() throws IOException {
        int chunkCount = 2048;
        byte[] plaintext = TestSupport.bytes(chunkCount * CHUNK_SIZE, 23);
        byte[] baseA = new byte[12];
        byte[] baseB = new byte[12];
        Arrays.fill(baseA, (byte) 0x11);
        Arrays.fill(baseB, (byte) 0x22);
        StreamHeader headerA = headerWithNonce(AlgorithmId.AES_GCM, CHUNK_SIZE,
                AAD.ofUtf8("unique"), Nonce.of(baseA));
        StreamHeader headerB = headerWithNonce(AlgorithmId.AES_GCM, CHUNK_SIZE,
                AAD.ofUtf8("unique"), Nonce.of(baseB));
        RecordingOnlyCipher cipherA = new RecordingOnlyCipher(AlgorithmId.AES_GCM);
        RecordingOnlyCipher cipherB = new RecordingOnlyCipher(AlgorithmId.AES_GCM);
        encrypt(headerA, KEY, plaintext, cipherA);
        encrypt(headerB, KEY, plaintext, cipherB);

        assertEquals(chunkCount, cipherA.nonces.size());
        assertEquals(chunkCount, cipherB.nonces.size());
        assertArrayEquals(baseA, cipherA.nonces.get(0).asBytes());
        assertArrayEquals(baseB, cipherB.nonces.get(0).asBytes());

        Set<String> distinct = new HashSet<>();
        for (Nonce nonce : concat(cipherA.nonces, cipherB.nonces)) {
            String encoded = HexFormat.of().formatHex(nonce.asBytes());
            assertTrue(distinct.add(encoded), "duplicate chunk nonce " + encoded);
        }
        assertEquals(2 * chunkCount, distinct.size());
    }

    @Test
    void streamChunkIndexBeyondTheEncodableRangeIsRejected() throws Exception {
        StreamHeader header = headerWithNonce(AlgorithmId.AES_GCM, CHUNK_SIZE,
                AAD.empty(), Nonce.of(TestSupport.bytes(12, 24)));
        byte[] encodedHeader = headerBytes(header);
        byte[] headerHash = MessageDigest.getInstance("SHA-256").digest(encodedHeader);

        long maxIndex = 0xFFFFFFFFL;
        AeadCipher cipher = PROVIDER.aeadCipher(AlgorithmId.AES_GCM);
        AeadCipher.AeadResult result = cipher.encrypt(KEY, TestSupport.bytes(CHUNK_SIZE, 25),
                AeadStreamCipherService.chunkNonce(header.baseNonce(), maxIndex),
                chunkAad(headerHash, maxIndex, false));

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.writeBytes(encodedHeader);
        writeFrame(stream, result.ciphertext(), result.tag());
        writeFrame(stream, new byte[CHUNK_SIZE], new byte[16]);

        ByteArrayInputStream input = new ByteArrayInputStream(stream.toByteArray());
        StreamHeader readHeader = SERVICE.readHeader(input);
        try (InputStream decrypting = SERVICE.openDecrypting(input, readHeader, cipher, KEY,
                maxIndex)) {
            CryptoException exception = assertThrows(CryptoException.class,
                    decrypting::readAllBytes);
            assertEquals(ErrorCode.STREAM_LIMIT_EXCEEDED, exception.errorCode());
        }
    }

    @Test
    void streamRejectsCiphersWithNonTwelveByteNonces() throws IOException {
        StreamHeader header = new StreamHeader(StreamHeader.CURRENT_VERSION, AlgorithmId.AES_CBC,
                KeyId.of("etm"), KeyVersion.first(), Nonce.of(TestSupport.bytes(16, 19)),
                CHUNK_SIZE, AAD.empty(), Instant.now(), Map.of());
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        SERVICE.writeHeader(output, header);
        CryptoException exception = assertThrows(CryptoException.class,
                () -> SERVICE.openEncrypting(output, header,
                        PROVIDER.aeadCipher(AlgorithmId.AES_CBC), KEY));
        assertEquals(ErrorCode.UNSUPPORTED_OPERATION, exception.errorCode());
    }

    @Test
    void chacha20Poly1305StreamRoundtrip() throws IOException {
        SecretKey key = TestSupport.chaChaKey(16);
        StreamHeader header = header(AlgorithmId.CHACHA20_POLY1305, 2048, AAD.ofUtf8("chacha"));
        byte[] plaintext = TestSupport.bytes(9000, 17);
        byte[] stream = encrypt(header, key, plaintext);
        StreamHeader readHeader = readHeader(stream);
        assertArrayEquals(plaintext, decrypt(stream, key));
        assertEquals(AlgorithmId.CHACHA20_POLY1305, readHeader.algorithm());
    }

    // ---------------------------------------------------------------- helpers

    private static StreamHeader header(AlgorithmId algorithm, int chunkSize, AAD aad) {
        return headerWithNonce(algorithm, chunkSize, aad, Nonce.of(TestSupport.bytes(12, 99)));
    }

    private static StreamHeader headerWithNonce(AlgorithmId algorithm, int chunkSize, AAD aad,
                                                Nonce nonce) {
        return new StreamHeader(StreamHeader.CURRENT_VERSION, algorithm, KeyId.of("test-key-1"),
                KeyVersion.of(3), nonce, chunkSize, aad,
                Instant.ofEpochMilli(1_700_000_000_000L), Map.of("b", "2", "a", "1"));
    }

    private static byte[] encrypt(StreamHeader header, SecretKey key, byte[] plaintext)
            throws IOException {
        return encrypt(header, key, plaintext, PROVIDER.aeadCipher(header.algorithm()));
    }

    private static byte[] encrypt(StreamHeader header, SecretKey key, byte[] plaintext,
                                  AeadCipher cipher) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        SERVICE.writeHeader(output, header);
        try (OutputStream encrypting = SERVICE.openEncrypting(output, header, cipher, key)) {
            encrypting.write(plaintext);
        }
        return output.toByteArray();
    }

    private static List<Nonce> concat(List<Nonce> first, List<Nonce> second) {
        List<Nonce> all = new ArrayList<>(first.size() + second.size());
        all.addAll(first);
        all.addAll(second);
        return all;
    }

    private static int intAt(byte[] value, int offset) {
        return ((value[offset] & 0xff) << 24) | ((value[offset + 1] & 0xff) << 16)
                | ((value[offset + 2] & 0xff) << 8) | (value[offset + 3] & 0xff);
    }

    private static AAD chunkAad(byte[] headerHash, long chunkIndex, boolean last) {
        byte[] encoded = new byte[4 + headerHash.length + 8 + 1];
        System.arraycopy(headerHash, 0, encoded, 4, headerHash.length);
        int offset = 4 + headerHash.length;
        for (int shift = 56; shift >= 0; shift -= 8) {
            encoded[offset++] = (byte) (chunkIndex >>> shift);
        }
        encoded[offset] = (byte) (last ? 1 : 0);
        return AAD.of(encoded);
    }

    private static void writeFrame(ByteArrayOutputStream output, byte[] ciphertext, byte[] tag) {
        int payloadLength = ciphertext.length + tag.length;
        output.write((payloadLength >>> 24) & 0xff);
        output.write((payloadLength >>> 16) & 0xff);
        output.write((payloadLength >>> 8) & 0xff);
        output.write(payloadLength & 0xff);
        output.writeBytes(ciphertext);
        output.writeBytes(tag);
    }

    private static StreamHeader readHeader(byte[] stream) throws IOException {
        return SERVICE.readHeader(new ByteArrayInputStream(stream));
    }

    private static byte[] decrypt(byte[] stream, SecretKey key) throws IOException {
        ByteArrayInputStream input = new ByteArrayInputStream(stream);
        StreamHeader header = SERVICE.readHeader(input);
        try (InputStream decrypting = SERVICE.openDecrypting(input, header,
                PROVIDER.aeadCipher(header.algorithm()), key, 0)) {
            return decrypting.readAllBytes();
        }
    }

    private static CryptoException decryptExpectingFailure(byte[] stream, SecretKey key)
            throws IOException {
        ByteArrayInputStream input = new ByteArrayInputStream(stream);
        StreamHeader header = SERVICE.readHeader(input);
        InputStream decrypting = SERVICE.openDecrypting(input, header,
                PROVIDER.aeadCipher(header.algorithm()), key, 0);
        return assertThrows(CryptoException.class, decrypting::readAllBytes);
    }

    private static byte[] headerBytes(StreamHeader header) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        SERVICE.writeHeader(output, header);
        return output.toByteArray();
    }

    private static int headerLength(StreamHeader header) throws IOException {
        return headerBytes(header).length;
    }

    private static final class RecordingCipher implements AeadCipher {

        private final AeadCipher delegate;
        private final List<Nonce> nonces = new ArrayList<>();
        private final List<AAD> aads = new ArrayList<>();

        RecordingCipher(AeadCipher delegate) {
            this.delegate = delegate;
        }

        @Override
        public AlgorithmId algorithm() {
            return delegate.algorithm();
        }

        @Override
        public int nonceLength() {
            return delegate.nonceLength();
        }

        @Override
        public int tagLength() {
            return delegate.tagLength();
        }

        @Override
        public AeadResult encrypt(SecretKey key, byte[] plaintext, Nonce nonce, AAD aad) {
            nonces.add(nonce);
            aads.add(aad);
            return delegate.encrypt(key, plaintext, nonce, aad);
        }

        @Override
        public byte[] decrypt(SecretKey key, Nonce nonce, byte[] ciphertext, byte[] tag, AAD aad) {
            return delegate.decrypt(key, nonce, ciphertext, tag, aad);
        }
    }

    /** Records chunk nonces without performing real encryption. */
    private static final class RecordingOnlyCipher implements AeadCipher {

        private final AlgorithmId algorithm;
        private final List<Nonce> nonces = new ArrayList<>();

        RecordingOnlyCipher(AlgorithmId algorithm) {
            this.algorithm = algorithm;
        }

        @Override
        public AlgorithmId algorithm() {
            return algorithm;
        }

        @Override
        public int nonceLength() {
            return 12;
        }

        @Override
        public int tagLength() {
            return 16;
        }

        @Override
        public AeadResult encrypt(SecretKey key, byte[] plaintext, Nonce nonce, AAD aad) {
            nonces.add(nonce);
            return new AeadResult(nonce, plaintext, new byte[16]);
        }

        @Override
        public byte[] decrypt(SecretKey key, Nonce nonce, byte[] ciphertext, byte[] tag, AAD aad) {
            throw new UnsupportedOperationException("decrypt is not used by this test double");
        }
    }

    private static final class TrackingOutputStream extends ByteArrayOutputStream {
        private boolean closed;
        private int flushes;

        @Override
        public void close() throws IOException {
            closed = true;
            super.close();
        }

        @Override
        public void flush() throws IOException {
            flushes++;
            super.flush();
        }
    }

    private static final class TrackingInputStream extends ByteArrayInputStream {
        private boolean closed;

        TrackingInputStream(byte[] data) {
            super(data);
        }

        @Override
        public void close() throws IOException {
            closed = true;
            super.close();
        }
    }
}
