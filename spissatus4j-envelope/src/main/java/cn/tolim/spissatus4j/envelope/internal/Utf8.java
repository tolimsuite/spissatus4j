package cn.tolim.spissatus4j.envelope.internal;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Strict UTF-8 helpers that reject malformed byte sequences. */
public final class Utf8 {

    private static final int VALIDATION_BUFFER_CHARS = 1024;

    private Utf8() {
    }

    public static String decode(byte[] bytes) {
        return decode(bytes, 0, bytes.length);
    }

    public static String decode(byte[] bytes, int offset, int length) {
        try {
            var decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            return decoder.decode(ByteBuffer.wrap(bytes, offset, length)).toString();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Invalid UTF-8 sequence");
        }
    }

    /**
     * Validates that the whole buffer is well-formed UTF-8 without allocating
     * a decoded copy. Rejects malformed sequences and lone surrogates encoded
     * as CESU-8/WTF-8. Throws {@link IllegalArgumentException} on failure.
     */
    public static void validate(byte[] bytes) {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        ByteBuffer input = ByteBuffer.wrap(bytes);
        CharBuffer output = CharBuffer.allocate(VALIDATION_BUFFER_CHARS);
        try {
            while (true) {
                CoderResult result = decoder.decode(input, output, true);
                if (result.isOverflow()) {
                    output.clear();
                    continue;
                }
                if (result.isError()) {
                    result.throwException();
                }
                break;
            }
            while (true) {
                CoderResult result = decoder.flush(output);
                if (result.isOverflow()) {
                    output.clear();
                    continue;
                }
                if (result.isError()) {
                    result.throwException();
                }
                return;
            }
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Invalid UTF-8 sequence");
        }
    }

    /**
     * Returns {@code true} when the string contains no unpaired surrogate, so
     * that it can be encoded to UTF-8 without lossy replacement.
     */
    public static boolean isWellFormed(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (index + 1 >= value.length()
                        || !Character.isLowSurrogate(value.charAt(index + 1))) {
                    return false;
                }
                index++;
            } else if (Character.isLowSurrogate(character)) {
                return false;
            }
        }
        return true;
    }

    public static byte[] encode(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    public static int length(String value) {
        return encode(value).length;
    }
}