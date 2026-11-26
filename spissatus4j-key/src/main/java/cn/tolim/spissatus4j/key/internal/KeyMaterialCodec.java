package cn.tolim.spissatus4j.key.internal;

import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Encodes and decodes provider-neutral key material.
 *
 * <p>A key pair is stored as two length-prefixed DER blocks: the PKCS#8
 * private key followed by the X.509 public key. The 4-byte lengths are
 * big-endian.</p>
 */
public final class KeyMaterialCodec {

    public static final String RAW = "RAW";
    public static final String PKCS8 = "PKCS8";
    public static final String X509 = "X509";
    public static final String KEYPAIR = "KEYPAIR";

    private static final Pattern PEM_BLOCK =
            Pattern.compile("-----BEGIN ([A-Z0-9 ]+)-----([\\s\\S]*?)-----END \\1-----");

    private KeyMaterialCodec() {
    }

    public static byte[] encodeKeyPair(byte[] privateDer, byte[] publicDer) {
        if (privateDer == null || privateDer.length == 0 || publicDer == null || publicDer.length == 0) {
            throw malformedPair();
        }
        ByteBuffer buffer = ByteBuffer.allocate(4 + privateDer.length + 4 + publicDer.length);
        buffer.putInt(privateDer.length).put(privateDer);
        buffer.putInt(publicDer.length).put(publicDer);
        return buffer.array();
    }

    public static KeyPairParts decodeKeyPair(byte[] encoded) {
        if (encoded == null || encoded.length < 8) {
            throw malformedPair();
        }
        try {
            ByteBuffer buffer = ByteBuffer.wrap(encoded);
            int privateLength = buffer.getInt();
            if (privateLength <= 0 || privateLength > buffer.remaining() - 4) {
                throw malformedPair();
            }
            byte[] privateDer = new byte[privateLength];
            buffer.get(privateDer);
            int publicLength = buffer.getInt();
            if (publicLength <= 0 || publicLength != buffer.remaining()) {
                throw malformedPair();
            }
            byte[] publicDer = new byte[publicLength];
            buffer.get(publicDer);
            return new KeyPairParts(privateDer, publicDer);
        } catch (RuntimeException e) {
            throw malformedPair();
        }
    }

    public static PemBlock pemBlock(byte[] material) {
        if (material == null || material.length == 0) {
            throw pemFailure();
        }
        String text = new String(material, StandardCharsets.UTF_8);
        Matcher matcher = PEM_BLOCK.matcher(text);
        if (!matcher.find()) {
            throw pemFailure();
        }
        String label = matcher.group(1).trim();
        String body = matcher.group(2).replaceAll("\\s", "");
        try {
            return new PemBlock(label, Base64.getDecoder().decode(body));
        } catch (IllegalArgumentException e) {
            throw pemFailure();
        }
    }

    public static boolean isKnownMaterialFormat(String format) {
        return RAW.equals(format) || PKCS8.equals(format) || X509.equals(format)
                || KEYPAIR.equals(format);
    }

    private static KeyException malformedPair() {
        return new KeyException(ErrorCode.KEY_PROVIDER_FAILURE, "Malformed key pair material");
    }

    private static KeyException pemFailure() {
        return new KeyException(ErrorCode.KEY_IMPORT_FAILED, "Invalid PEM encoding");
    }

    /** Decoded PEM block. */
    public record PemBlock(String label, byte[] der) {
        public PemBlock {
            if (label == null || label.isBlank() || der == null || der.length == 0) {
                throw new KeyException(ErrorCode.KEY_IMPORT_FAILED, "Invalid PEM encoding");
            }
            der = der.clone();
        }

        @Override
        public byte[] der() {
            return der.clone();
        }
    }

    /** Decoded key pair DER blocks. */
    public record KeyPairParts(byte[] privateDer, byte[] publicDer) {
        public KeyPairParts {
            privateDer = privateDer.clone();
            publicDer = publicDer.clone();
        }

        @Override
        public byte[] privateDer() {
            return privateDer.clone();
        }

        @Override
        public byte[] publicDer() {
            return publicDer.clone();
        }
    }
}