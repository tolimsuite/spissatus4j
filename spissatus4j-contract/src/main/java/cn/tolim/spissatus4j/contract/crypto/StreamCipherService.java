package cn.tolim.spissatus4j.contract.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.SecretKey;

/**
 * Canonical chunked AEAD stream format. Chunks are individually authenticated
 * and ordered through their index in the AAD, so tampering, truncation and
 * reordering are detected. Resume from a chunk boundary is supported.
 */
public interface StreamCipherService {

    String formatId();

    void writeHeader(OutputStream output, StreamHeader header) throws IOException;

    StreamHeader readHeader(InputStream input) throws IOException;

    OutputStream openEncrypting(OutputStream output, StreamHeader header, AeadCipher cipher,
                                SecretKey key) throws IOException;

    /**
     * Opens a decrypting stream.
     *
     * @param startChunkIndex first chunk index expected in the input; use 0 for
     *                        normal decryption, or the resumed chunk for a
     *                        checkpointed transfer
     */
    InputStream openDecrypting(InputStream input, StreamHeader header, AeadCipher cipher,
                               SecretKey key, long startChunkIndex) throws IOException;

    /** Skips whole encrypted frames without decrypting them (not authenticated). */
    void skipChunks(InputStream input, StreamHeader header, long chunks) throws IOException;
}