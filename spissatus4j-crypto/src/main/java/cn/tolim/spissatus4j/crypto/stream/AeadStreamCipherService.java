package cn.tolim.spissatus4j.crypto.stream;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.StreamCipherService;
import cn.tolim.spissatus4j.contract.crypto.StreamHeader;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.key.KeyId;
import cn.tolim.spissatus4j.contract.key.KeyVersion;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.crypto.SecretKey;

/**
 * Canonical chunked AEAD stream format {@code SPISSATUS-AEAD-STREAM-1}.
 *
 * <p>Header layout: magic {@code SPS4STRM}, int version (1), length-prefixed
 * UTF-8 algorithm id, length-prefixed key id, long key version, length-prefixed
 * base nonce, int chunk size, length-prefixed user AAD, long createdAt epoch
 * millis, int attribute count followed by sorted length-prefixed keys and
 * values.</p>
 *
 * <p>Each frame is {@code int payloadLength, ciphertext, tag}. The per-chunk
 * AAD is the user AAD (length-prefixed), SHA-256 of the canonical header bytes,
 * the 8-byte big-endian chunk index and a one-byte final flag.</p>
 *
 * <p>Chunk nonces preserve every byte of the 12-byte base nonce: the
 * big-endian 32-bit chunk index is XORed into the final four bytes. XOR with
 * a fixed value is a bijection, so the per-chunk nonces are unique across the
 * whole supported range {@code 0..2^32 - 1}, and chunk 0 reuses the base nonce
 * unchanged. Two streams must not share their leading eight base-nonce bytes;
 * unlike replacing the trailing bytes, this derivation also ensures that base
 * nonces differing only in their final four bytes never yield the same nonce
 * for the same chunk index.</p>
 */
public final class AeadStreamCipherService implements StreamCipherService {

    public static final String FORMAT_ID = "SPISSATUS-AEAD-STREAM-1";

    private static final byte[] MAGIC = {'S', 'P', 'S', '4', 'S', 'T', 'R', 'M'};
    private static final int CURRENT_VERSION = 1;
    private static final int HEADER_MAX_BYTES = 1024 * 1024;
    private static final int TAG_BYTES = 16;
    private static final int CHUNK_NONCE_BYTES = 12;
    private static final int MAX_FRAME_OVERHEAD = 64 * 1024;
    private static final long MAX_CHUNK_INDEX = 0xFFFFFFFFL;
    private static final long NO_PENDING_FRAME = Long.MIN_VALUE;

    @Override
    public String formatId() {
        return FORMAT_ID;
    }

    @Override
    public void writeHeader(OutputStream output, StreamHeader header) throws IOException {
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(header, "header");
        output.write(encodeHeader(header));
        output.flush();
    }

    @Override
    public StreamHeader readHeader(InputStream input) throws IOException {
        Objects.requireNonNull(input, "input");
        CountingInputStream counting = new CountingInputStream(input);
        DataInputStream in = new DataInputStream(counting);
        try {
            byte[] magic = new byte[MAGIC.length];
            in.readFully(magic);
            if (!Arrays.equals(MAGIC, magic)) {
                throw corrupted("Invalid stream magic");
            }
            int version = in.readInt();
            if (version != CURRENT_VERSION) {
                throw corrupted("Unsupported stream version");
            }
            byte[] algorithmBytes = readLengthPrefixed(in, 256);
            byte[] keyIdBytes = readLengthPrefixed(in, 256);
            long keyVersion = in.readLong();
            byte[] nonceBytes = readLengthPrefixed(in, 64);
            int chunkSize = in.readInt();
            byte[] aadBytes = readLengthPrefixed(in, HEADER_MAX_BYTES);
            long createdAtMillis = in.readLong();
            int attributeCount = in.readInt();
            if (attributeCount < 0) {
                throw corrupted("Invalid stream attribute count");
            }
            Map<String, String> attributes = new LinkedHashMap<>();
            String previousKey = null;
            for (int i = 0; i < attributeCount; i++) {
                String key = decodeUtf8(readLengthPrefixed(in, HEADER_MAX_BYTES));
                String value = decodeUtf8(readLengthPrefixed(in, HEADER_MAX_BYTES));
                if (previousKey != null && previousKey.compareTo(key) >= 0) {
                    throw corrupted("Stream attributes are not canonically ordered");
                }
                previousKey = key;
                attributes.put(key, value);
            }
            if (counting.count() > HEADER_MAX_BYTES) {
                throw corrupted("Stream header exceeds 1 MiB");
            }
            AlgorithmId algorithm;
            KeyId keyId;
            Nonce baseNonce;
            try {
                if (nonceBytes.length < 8) {
                    throw corrupted("Stream base nonce is too short");
                }
                if (chunkSize < 1024 || chunkSize > 16 * 1024 * 1024) {
                    throw corrupted("Invalid stream chunk size");
                }
                algorithm = AlgorithmId.of(decodeUtf8(algorithmBytes));
                keyId = KeyId.of(decodeUtf8(keyIdBytes));
                baseNonce = Nonce.of(nonceBytes);
                return new StreamHeader(version, algorithm, keyId, KeyVersion.of(keyVersion),
                        baseNonce, chunkSize, AAD.of(aadBytes), Instant.ofEpochMilli(createdAtMillis),
                        attributes);
            } catch (IllegalArgumentException e) {
                throw corrupted("Invalid stream header value");
            }
        } catch (EOFException e) {
            throw corrupted("Truncated stream header");
        }
    }

    @Override
    public OutputStream openEncrypting(OutputStream output, StreamHeader header, AeadCipher cipher,
                                       SecretKey key) throws IOException {
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(header, "header");
        Objects.requireNonNull(cipher, "cipher");
        Objects.requireNonNull(key, "key");
        validateStreamCipher(header, cipher);
        return new EncryptingStream(output, header, cipher, key);
    }

    @Override
    public InputStream openDecrypting(InputStream input, StreamHeader header, AeadCipher cipher,
                                      SecretKey key, long startChunkIndex) throws IOException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(header, "header");
        Objects.requireNonNull(cipher, "cipher");
        Objects.requireNonNull(key, "key");
        validateStreamCipher(header, cipher);
        if (startChunkIndex < 0) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                    "Start chunk index must not be negative");
        }
        if (startChunkIndex > MAX_CHUNK_INDEX) {
            throw new CryptoException(ErrorCode.STREAM_LIMIT_EXCEEDED,
                    "Start chunk index exceeds the 32-bit stream range");
        }
        return new DecryptingStream(input, header, cipher, key, startChunkIndex);
    }

    @Override
    public void skipChunks(InputStream input, StreamHeader header, long chunks) throws IOException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(header, "header");
        if (chunks < 0) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                    "Chunk count must not be negative");
        }
        for (long i = 0; i < chunks; i++) {
            int payloadLength = readFrameLength(input);
            if (payloadLength == -1) {
                throw new CryptoException(ErrorCode.STREAM_TRUNCATED,
                        "Stream ended before the requested chunk");
            }
            validateFrameLength(payloadLength, header.chunkSize());
            skipFully(input, payloadLength);
        }
    }

    // ---------------------------------------------------------------- header

    private static byte[] encodeHeader(StreamHeader header) {
        if (header.version() != CURRENT_VERSION) {
            throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION,
                    "Only stream version " + CURRENT_VERSION + " is supported");
        }
        Objects.requireNonNull(header.algorithm(), "algorithm");
        Objects.requireNonNull(header.keyId(), "keyId");
        Objects.requireNonNull(header.baseNonce(), "baseNonce");
        Objects.requireNonNull(header.aad(), "aad");
        Objects.requireNonNull(header.createdAt(), "createdAt");
        byte[] nonce = header.baseNonce().asBytes();
        if (nonce.length < 8 || nonce.length > 64) {
            throw new CryptoException(ErrorCode.NONCE_INVALID,
                    "Stream base nonce must be between 8 and 64 bytes");
        }
        try (ByteArrayOutputStream buffer = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(buffer)) {
            out.write(MAGIC);
            out.writeInt(CURRENT_VERSION);
            writeLengthPrefixed(out, header.algorithm().id().getBytes(StandardCharsets.UTF_8));
            writeLengthPrefixed(out, header.keyId().value().getBytes(StandardCharsets.UTF_8));
            out.writeLong(header.keyVersion().value());
            writeLengthPrefixed(out, nonce);
            out.writeInt(header.chunkSize());
            writeLengthPrefixed(out, header.aad().asBytes());
            out.writeLong(header.createdAt().toEpochMilli());
            Map<String, String> attributes = header.attributes();
            List<String> keys = new ArrayList<>(attributes.keySet());
            Collections.sort(keys);
            out.writeInt(keys.size());
            for (String key : keys) {
                String value = attributes.get(key);
                writeLengthPrefixed(out, key.getBytes(StandardCharsets.UTF_8));
                writeLengthPrefixed(out, value.getBytes(StandardCharsets.UTF_8));
            }
            out.flush();
            byte[] encoded = buffer.toByteArray();
            if (encoded.length > HEADER_MAX_BYTES) {
                throw new CryptoException(ErrorCode.STREAM_LIMIT_EXCEEDED,
                        "Stream header exceeds 1 MiB");
            }
            return encoded;
        } catch (IOException e) {
            throw new CryptoException(ErrorCode.INTERNAL_ERROR, "Failed to encode stream header", e);
        }
    }

    private static void writeLengthPrefixed(DataOutputStream out, byte[] value) throws IOException {
        if (value.length > HEADER_MAX_BYTES) {
            throw new CryptoException(ErrorCode.STREAM_LIMIT_EXCEEDED,
                    "Stream header field exceeds 1 MiB");
        }
        out.writeInt(value.length);
        out.write(value);
    }

    private static byte[] readLengthPrefixed(DataInputStream in, int maxLength) throws IOException {
        int length = in.readInt();
        if (length < 0 || length > maxLength) {
            throw corrupted("Invalid length in stream header");
        }
        byte[] value = new byte[length];
        in.readFully(value);
        return value;
    }

    private static String decodeUtf8(byte[] value) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value))
                    .toString();
        } catch (CharacterCodingException e) {
            throw corrupted("Invalid UTF-8 in stream header");
        }
    }

    private static void validateStreamCipher(StreamHeader header, AeadCipher cipher) {
        if (header.version() != CURRENT_VERSION) {
            throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION,
                    "Only stream version " + CURRENT_VERSION + " is supported");
        }
        if (!header.algorithm().equals(cipher.algorithm())) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER,
                    "Stream header algorithm does not match the cipher");
        }
        if (cipher.nonceLength() != 12) {
            throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION,
                    "Stream cipher must use 12-byte nonces");
        }
        if (cipher.tagLength() != TAG_BYTES) {
            throw new CryptoException(ErrorCode.UNSUPPORTED_OPERATION,
                    "Stream cipher must use 16-byte tags");
        }
        if (header.baseNonce().length() != cipher.nonceLength()) {
            throw new CryptoException(ErrorCode.NONCE_INVALID,
                    "Stream base nonce must be " + cipher.nonceLength() + " bytes");
        }
    }

    // ------------------------------------------------------------- utilities

    private static byte[] headerHash(StreamHeader header) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(encodeHeader(header));
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE, "SHA-256 unavailable", e);
        }
    }

    private static AAD chunkAad(AAD userAad, byte[] headerHash, long chunkIndex, boolean last) {
        byte[] user = userAad.asBytes();
        int total = 4 + user.length + headerHash.length + 8 + 1;
        if (total > HEADER_MAX_BYTES) {
            throw new CryptoException(ErrorCode.STREAM_LIMIT_EXCEEDED,
                    "Chunk AAD exceeds 1 MiB");
        }
        byte[] encoded = new byte[total];
        int offset = 0;
        encoded[offset++] = (byte) (user.length >>> 24);
        encoded[offset++] = (byte) (user.length >>> 16);
        encoded[offset++] = (byte) (user.length >>> 8);
        encoded[offset++] = (byte) user.length;
        System.arraycopy(user, 0, encoded, offset, user.length);
        offset += user.length;
        System.arraycopy(headerHash, 0, encoded, offset, headerHash.length);
        offset += headerHash.length;
        for (int shift = 56; shift >= 0; shift -= 8) {
            encoded[offset++] = (byte) (chunkIndex >>> shift);
        }
        encoded[offset] = (byte) (last ? 1 : 0);
        return AAD.of(encoded);
    }

    static Nonce chunkNonce(Nonce baseNonce, long chunkIndex) {
        if (chunkIndex < 0 || chunkIndex > MAX_CHUNK_INDEX) {
            throw new CryptoException(ErrorCode.STREAM_LIMIT_EXCEEDED,
                    "Chunk index exceeds the 32-bit stream range");
        }
        byte[] nonce = baseNonce.asBytes();
        if (nonce.length != CHUNK_NONCE_BYTES) {
            throw new CryptoException(ErrorCode.NONCE_INVALID,
                    "Stream chunk nonces require a 12-byte base nonce");
        }
        // Preserve the entire base nonce and mix the big-endian chunk index
        // into its final four bytes with XOR. XOR is injective for a fixed
        // base nonce (each chunk index yields a distinct nonce), chunk 0 is
        // exactly the base nonce, and two base nonces that differ in their
        // final four bytes can never collapse to the same nonce for the same
        // chunk index. Replacing those bytes would discard 32 bits of the
        // supplied base nonce.
        nonce[CHUNK_NONCE_BYTES - 4] ^= (byte) (chunkIndex >>> 24);
        nonce[CHUNK_NONCE_BYTES - 3] ^= (byte) (chunkIndex >>> 16);
        nonce[CHUNK_NONCE_BYTES - 2] ^= (byte) (chunkIndex >>> 8);
        nonce[CHUNK_NONCE_BYTES - 1] ^= (byte) chunkIndex;
        return Nonce.of(nonce);
    }

    private static int readFrameLength(InputStream input) throws IOException {
        int first = input.read();
        if (first == -1) {
            return -1;
        }
        int second = input.read();
        int third = input.read();
        int fourth = input.read();
        if (second == -1 || third == -1 || fourth == -1) {
            throw new CryptoException(ErrorCode.STREAM_TRUNCATED, "Truncated stream frame header");
        }
        int length = ((first & 0xff) << 24) | ((second & 0xff) << 16) | ((third & 0xff) << 8)
                | (fourth & 0xff);
        if (length < 0) {
            // 0xFFFFFFFF must not be confused with the -1 EOF sentinel.
            throw corrupted("Invalid stream frame length");
        }
        return length;
    }

    private static void validateFrameLength(int payloadLength, int chunkSize) {
        if (payloadLength < TAG_BYTES) {
            throw corrupted("Invalid stream frame length");
        }
        if (payloadLength > chunkSize + MAX_FRAME_OVERHEAD) {
            throw new CryptoException(ErrorCode.STREAM_LIMIT_EXCEEDED,
                    "Stream frame exceeds the configured chunk limit");
        }
    }

    private static byte[] readFully(InputStream input, int length) throws IOException {
        byte[] value = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = input.read(value, offset, length - offset);
            if (read == -1) {
                throw new CryptoException(ErrorCode.STREAM_TRUNCATED, "Truncated stream frame");
            }
            offset += read;
        }
        return value;
    }

    private static void skipFully(InputStream input, int length) throws IOException {
        byte[] scratch = new byte[Math.min(length, 8192)];
        int remaining = length;
        try {
            while (remaining > 0) {
                int read = input.read(scratch, 0, Math.min(scratch.length, remaining));
                if (read == -1) {
                    throw new CryptoException(ErrorCode.STREAM_TRUNCATED, "Truncated stream frame");
                }
                remaining -= read;
            }
        } finally {
            Arrays.fill(scratch, (byte) 0);
        }
    }

    private static CryptoException corrupted(String message) {
        return new CryptoException(ErrorCode.STREAM_CORRUPTED, message);
    }

    // ------------------------------------------------------------- encryption

    private static final class EncryptingStream extends OutputStream {

        private final OutputStream output;
        private final DataOutputStream frames;
        private final AeadCipher cipher;
        private final SecretKey key;
        private final AAD userAad;
        private final byte[] headerHash;
        private final byte[] buffer;
        private final int chunkSize;
        private final Nonce baseNonce;
        private int buffered;
        private long chunkIndex;
        private boolean closed;

        EncryptingStream(OutputStream output, StreamHeader header, AeadCipher cipher, SecretKey key) {
            this.output = output;
            this.frames = new DataOutputStream(output);
            this.cipher = cipher;
            this.key = key;
            this.userAad = header.aad();
            this.headerHash = headerHash(header);
            this.chunkSize = header.chunkSize();
            this.buffer = new byte[chunkSize];
            this.baseNonce = header.baseNonce();
        }

        @Override
        public void write(int value) throws IOException {
            ensureOpen();
            if (buffered == chunkSize) {
                emitChunk(false);
            }
            buffer[buffered++] = (byte) value;
        }

        @Override
        public void write(byte[] data, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, Objects.requireNonNull(data, "data").length);
            ensureOpen();
            int remaining = length;
            int position = offset;
            while (remaining > 0) {
                if (buffered == chunkSize) {
                    emitChunk(false);
                }
                int copy = Math.min(remaining, chunkSize - buffered);
                System.arraycopy(data, position, buffer, buffered, copy);
                buffered += copy;
                position += copy;
                remaining -= copy;
            }
        }

        @Override
        public void flush() throws IOException {
            ensureOpen();
            output.flush();
        }

        @Override
        public void close() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            try {
                emitChunk(true);
                output.flush();
            } finally {
                Arrays.fill(buffer, (byte) 0);
            }
        }

        private void emitChunk(boolean last) throws IOException {
            if (chunkIndex > MAX_CHUNK_INDEX) {
                throw new CryptoException(ErrorCode.STREAM_LIMIT_EXCEEDED,
                        "Stream chunk limit exceeded");
            }
            byte[] plaintext = Arrays.copyOf(buffer, buffered);
            try {
                AAD aad = chunkAad(userAad, headerHash, chunkIndex, last);
                Nonce nonce = chunkNonce(baseNonce, chunkIndex);
                AeadCipher.AeadResult result = cipher.encrypt(key, plaintext, nonce, aad);
                byte[] ciphertext = result.ciphertext();
                byte[] tag = result.tag();
                if (tag.length != TAG_BYTES) {
                    throw new CryptoException(ErrorCode.INTERNAL_ERROR,
                            "AEAD cipher returned an unexpected tag length");
                }
                int payloadLength = ciphertext.length + tag.length;
                if (payloadLength > chunkSize + MAX_FRAME_OVERHEAD) {
                    throw new CryptoException(ErrorCode.STREAM_LIMIT_EXCEEDED,
                            "Stream frame exceeds the configured chunk limit");
                }
                frames.writeInt(payloadLength);
                frames.write(ciphertext);
                frames.write(tag);
                chunkIndex++;
                buffered = 0;
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        }

        private void ensureOpen() throws IOException {
            if (closed) {
                throw new IOException("Stream is closed");
            }
        }
    }

    // ------------------------------------------------------------- decryption

    private static final class DecryptingStream extends InputStream {

        private final InputStream input;
        private final AeadCipher cipher;
        private final SecretKey key;
        private final AAD userAad;
        private final byte[] headerHash;
        private final Nonce baseNonce;
        private final int chunkSize;
        private final long startChunkIndex;

        private long expectedIndex;
        private long pendingLength = NO_PENDING_FRAME;
        private byte[] plaintext = new byte[0];
        private int position;
        private int limit;
        private boolean finished;
        private boolean closed;

        DecryptingStream(InputStream input, StreamHeader header, AeadCipher cipher, SecretKey key,
                         long startChunkIndex) {
            this.input = input;
            this.cipher = cipher;
            this.key = key;
            this.userAad = header.aad();
            this.headerHash = headerHash(header);
            this.baseNonce = header.baseNonce();
            this.chunkSize = header.chunkSize();
            this.startChunkIndex = startChunkIndex;
            this.expectedIndex = startChunkIndex;
        }

        @Override
        public int read() throws IOException {
            ensureOpen();
            byte[] single = new byte[1];
            int read = read(single, 0, 1);
            return read == -1 ? -1 : single[0] & 0xff;
        }

        @Override
        public int read(byte[] data, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, Objects.requireNonNull(data, "data").length);
            ensureOpen();
            if (length == 0) {
                return 0;
            }
            while (position == limit) {
                if (!fill()) {
                    return -1;
                }
            }
            int copy = Math.min(length, limit - position);
            System.arraycopy(plaintext, position, data, offset, copy);
            position += copy;
            return copy;
        }

        @Override
        public void close() throws IOException {
            // Close-shield: the caller owns the underlying stream.
            if (!closed) {
                closed = true;
                if (plaintext != null) {
                    Arrays.fill(plaintext, (byte) 0);
                }
                plaintext = new byte[0];
                position = 0;
                limit = 0;
            }
        }

        private boolean fill() throws IOException {
            Arrays.fill(plaintext, (byte) 0);
            plaintext = new byte[0];
            position = 0;
            limit = 0;
            if (finished) {
                return false;
            }
            if (expectedIndex > MAX_CHUNK_INDEX) {
                throw new CryptoException(ErrorCode.STREAM_LIMIT_EXCEEDED,
                        "Stream chunk limit exceeded");
            }
            int payloadLength;
            if (pendingLength != NO_PENDING_FRAME) {
                payloadLength = Math.toIntExact(pendingLength);
                pendingLength = NO_PENDING_FRAME;
            } else {
                payloadLength = readFrameLength(input);
                if (payloadLength == -1) {
                    if (expectedIndex == startChunkIndex) {
                        throw new CryptoException(ErrorCode.STREAM_TRUNCATED,
                                "Stream contains no chunks");
                    }
                    throw new CryptoException(ErrorCode.STREAM_TRUNCATED,
                            "Stream ended before a final chunk");
                }
            }
            validateFrameLength(payloadLength, chunkSize);
            byte[] frame = readFully(input, payloadLength);
            byte[] plaintextBytes;
            try {
                int nextPayloadLength = readFrameLength(input);
                boolean last = nextPayloadLength == -1;
                pendingLength = nextPayloadLength == -1 ? NO_PENDING_FRAME : nextPayloadLength;
                byte[] tag = Arrays.copyOfRange(frame, payloadLength - TAG_BYTES, payloadLength);
                byte[] ciphertext = Arrays.copyOf(frame, payloadLength - TAG_BYTES);
                try {
                    plaintextBytes = decryptChunk(ciphertext, tag, last);
                } finally {
                    Arrays.fill(ciphertext, (byte) 0);
                    Arrays.fill(tag, (byte) 0);
                }
                if (plaintextBytes.length > chunkSize) {
                    Arrays.fill(plaintextBytes, (byte) 0);
                    throw corrupted("Stream chunk exceeds the configured chunk size");
                }
                if (!last && plaintextBytes.length != chunkSize) {
                    Arrays.fill(plaintextBytes, (byte) 0);
                    throw corrupted("Non-final stream chunk has an invalid size");
                }
                expectedIndex++;
                if (last) {
                    finished = true;
                }
            } finally {
                Arrays.fill(frame, (byte) 0);
            }
            plaintext = plaintextBytes;
            limit = plaintextBytes.length;
            return true;
        }

        private byte[] decryptChunk(byte[] ciphertext, byte[] tag, boolean last) {
            byte[] plaintextBytes = attempt(ciphertext, tag, last);
            if (plaintextBytes != null) {
                return plaintextBytes;
            }
            byte[] alternate = attempt(ciphertext, tag, !last);
            if (alternate != null) {
                Arrays.fill(alternate, (byte) 0);
                if (last) {
                    throw new CryptoException(ErrorCode.STREAM_TRUNCATED,
                            "Stream ended before the final chunk");
                }
                throw new CryptoException(ErrorCode.STREAM_ORDER_VIOLATION,
                        "Stream chunk ordering violation");
            }
            throw corrupted("Stream chunk authentication failed");
        }

        private byte[] attempt(byte[] ciphertext, byte[] tag, boolean last) {
            try {
                return cipher.decrypt(key, chunkNonce(baseNonce, expectedIndex), ciphertext, tag,
                        chunkAad(userAad, headerHash, expectedIndex, last));
            } catch (CryptoException e) {
                return null;
            }
        }

        private void ensureOpen() throws IOException {
            if (closed) {
                throw new IOException("Stream is closed");
            }
        }
    }

    /** Counts header bytes so a malformed length cannot force unbounded reads. */
    private static final class CountingInputStream extends FilterInputStream {

        private long count;

        CountingInputStream(InputStream input) {
            super(input);
        }

        long count() {
            return count;
        }

        @Override
        public int read() throws IOException {
            int value = super.read();
            if (value != -1) {
                increment(1);
            }
            return value;
        }

        @Override
        public int read(byte[] data, int offset, int length) throws IOException {
            int read = super.read(data, offset, length);
            if (read > 0) {
                increment(read);
            }
            return read;
        }

        private void increment(int bytes) {
            count += bytes;
            if (count > HEADER_MAX_BYTES) {
                throw corrupted("Stream header exceeds 1 MiB");
            }
        }
    }
}
