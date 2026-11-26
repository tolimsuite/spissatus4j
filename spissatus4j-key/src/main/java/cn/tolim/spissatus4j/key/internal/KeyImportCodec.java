package cn.tolim.spissatus4j.key.internal;

import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.exception.KeyException;
import cn.tolim.spissatus4j.contract.key.ImportFormat;
import cn.tolim.spissatus4j.contract.key.KeyImportRequest;
import cn.tolim.spissatus4j.contract.key.KeyType;
import cn.tolim.spissatus4j.key.internal.KeyMaterialCodec.PemBlock;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Objects;

/**
 * Decodes import material into canonical provider-neutral encodings.
 *
 * <p>Input is never logged. Decryption of password-protected PEM is not
 * supported; such imports fail with a generic import error.</p>
 */
public final class KeyImportCodec {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private KeyImportCodec() {
    }

    public static ImportedMaterial decode(KeyImportRequest request) {
        Objects.requireNonNull(request, "request");
        try {
            return switch (request.format()) {
                case RAW -> fromRaw(request);
                case PKCS8 -> fromPkcs8(request);
                case X509 -> fromX509(request);
                case PEM -> fromPem(request);
                case JWK -> fromJwk(request);
            };
        } catch (KeyException e) {
            throw e;
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new KeyException(ErrorCode.KEY_IMPORT_FAILED, "Key import failed");
        }
    }

    private static ImportedMaterial fromRaw(KeyImportRequest request) {
        if (KeySupport.isAsymmetric(request.type())) {
            throw importFailure("RAW import requires a symmetric key type");
        }
        byte[] raw = request.material();
        try {
            validateSymmetricLength(request.type(), raw.length);
            return new ImportedMaterial(KeyMaterialCodec.RAW, raw, raw.length * 8);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    private static ImportedMaterial fromPkcs8(KeyImportRequest request) throws GeneralSecurityException {
        if (!KeySupport.isAsymmetric(request.type())) {
            throw importFailure("PKCS8 import requires an asymmetric key type");
        }
        byte[] encoded = request.material();
        PrivateKey key = KeySupport.keyFactory(request.type())
                .generatePrivate(new PKCS8EncodedKeySpec(encoded));
        byte[] canonical = key.getEncoded();
        try {
            return new ImportedMaterial(KeyMaterialCodec.PKCS8, canonical, keyBits(key, request.type()));
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static ImportedMaterial fromX509(KeyImportRequest request) throws GeneralSecurityException {
        if (!KeySupport.isAsymmetric(request.type())) {
            throw importFailure("X509 import requires an asymmetric key type");
        }
        byte[] encoded = request.material();
        PublicKey key = KeySupport.keyFactory(request.type())
                .generatePublic(new X509EncodedKeySpec(encoded));
        byte[] canonical = key.getEncoded();
        try {
            return new ImportedMaterial(KeyMaterialCodec.X509, canonical, keyBits(key, request.type()));
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static ImportedMaterial fromPem(KeyImportRequest request) throws GeneralSecurityException {
        if (!KeySupport.isAsymmetric(request.type())) {
            throw importFailure("PEM import requires an asymmetric key type");
        }
        if (request.password() != null) {
            throw importFailure("Password-protected PEM import is not supported");
        }
        PemBlock block = KeyMaterialCodec.pemBlock(request.material());
        KeyFactory factory = KeySupport.keyFactory(request.type());
        String label = block.label().toUpperCase(Locale.ROOT);
        byte[] der = block.der();
        try {
            if ("PRIVATE KEY".equals(label)) {
                PrivateKey key = factory.generatePrivate(new PKCS8EncodedKeySpec(der));
                return new ImportedMaterial(KeyMaterialCodec.PKCS8, key.getEncoded(),
                        keyBits(key, request.type()));
            }
            if ("PUBLIC KEY".equals(label)) {
                PublicKey key = factory.generatePublic(new X509EncodedKeySpec(der));
                return new ImportedMaterial(KeyMaterialCodec.X509, key.getEncoded(),
                        keyBits(key, request.type()));
            }
        } finally {
            Arrays.fill(der, (byte) 0);
        }
        throw importFailure("Unsupported PEM block type");
    }

    private static ImportedMaterial fromJwk(KeyImportRequest request) throws GeneralSecurityException {
        JsonNode jwk;
        try {
            jwk = MAPPER.readTree(request.material());
        } catch (IOException e) {
            throw importFailure("JWK is not valid JSON");
        }
        if (jwk == null || !jwk.isObject()) {
            throw importFailure("JWK is not valid JSON");
        }
        String keyType = text(jwk, "kty");
        return switch (keyType) {
            case "oct" -> jwkOct(request, jwk);
            case "RSA" -> jwkRsa(request, jwk);
            case "EC" -> jwkEc(request, jwk);
            default -> throw importFailure("Unsupported JWK key type");
        };
    }

    private static ImportedMaterial jwkOct(KeyImportRequest request, JsonNode jwk) {
        KeyType type = request.type();
        if (KeySupport.isAsymmetric(type)) {
            throw importFailure("JWK oct keys require a symmetric key type");
        }
        byte[] raw = base64Url(text(jwk, "k"));
        try {
            validateSymmetricLength(type, raw.length);
            return new ImportedMaterial(KeyMaterialCodec.RAW, raw, raw.length * 8);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    private static ImportedMaterial jwkRsa(KeyImportRequest request, JsonNode jwk)
            throws GeneralSecurityException {
        if (request.type() != KeyType.RSA) {
            throw importFailure("JWK RSA keys require the RSA key type");
        }
        BigInteger modulus = new BigInteger(1, base64Url(text(jwk, "n")));
        BigInteger exponent = new BigInteger(1, base64Url(text(jwk, "e")));
        KeyFactory factory = KeySupport.keyFactory(KeyType.RSA);
        PublicKey publicKey = factory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
        JsonNode privateExponent = jwk.get("d");
        if (privateExponent == null || privateExponent.isNull()) {
            return new ImportedMaterial(KeyMaterialCodec.X509, publicKey.getEncoded(),
                    modulus.bitLength());
        }
        BigInteger d = new BigInteger(1, base64Url(privateExponent.asText()));
        RSAPrivateKeySpec privateSpec;
        if (jwk.hasNonNull("p") && jwk.hasNonNull("q")) {
            BigInteger p = new BigInteger(1, base64Url(jwk.get("p").asText()));
            BigInteger q = new BigInteger(1, base64Url(jwk.get("q").asText()));
            BigInteger dp = jwk.hasNonNull("dp")
                    ? new BigInteger(1, base64Url(jwk.get("dp").asText()))
                    : d.mod(p.subtract(BigInteger.ONE));
            BigInteger dq = jwk.hasNonNull("dq")
                    ? new BigInteger(1, base64Url(jwk.get("dq").asText()))
                    : d.mod(q.subtract(BigInteger.ONE));
            BigInteger qi = jwk.hasNonNull("qi")
                    ? new BigInteger(1, base64Url(jwk.get("qi").asText()))
                    : q.modInverse(p);
            privateSpec = new RSAPrivateCrtKeySpec(modulus, exponent, d, p, q, dp, dq, qi);
        } else {
            privateSpec = new RSAPrivateKeySpec(modulus, d);
        }
        PrivateKey privateKey = factory.generatePrivate(privateSpec);
        byte[] material = KeyMaterialCodec.encodeKeyPair(privateKey.getEncoded(),
                publicKey.getEncoded());
        return new ImportedMaterial(KeyMaterialCodec.KEYPAIR, material, modulus.bitLength());
    }

    private static ImportedMaterial jwkEc(KeyImportRequest request, JsonNode jwk)
            throws GeneralSecurityException {
        KeyType type = request.type();
        if (type != KeyType.EC && type != KeyType.SM2) {
            throw importFailure("JWK EC keys require the EC or SM2 key type");
        }
        String curve = text(jwk, "crv");
        String parameterName = switch (curve) {
            case "P-256" -> "secp256r1";
            case "P-384" -> "secp384r1";
            case "sm2p256v1" -> "sm2p256v1";
            default -> throw importFailure("Unsupported JWK curve");
        };
        ECParameterSpec parameters = ecParameters(parameterName);
        KeyFactory factory = KeySupport.keyFactory(type);
        BigInteger x = new BigInteger(1, base64Url(text(jwk, "x")));
        BigInteger y = new BigInteger(1, base64Url(text(jwk, "y")));
        ECPoint point = new ECPoint(x, y);
        PublicKey publicKey = factory.generatePublic(new ECPublicKeySpec(point, parameters));
        if (!jwk.hasNonNull("d")) {
            return new ImportedMaterial(KeyMaterialCodec.X509, publicKey.getEncoded(),
                    parameters.getCurve().getField().getFieldSize());
        }
        BigInteger d = new BigInteger(1, base64Url(jwk.get("d").asText()));
        PrivateKey privateKey = factory.generatePrivate(new ECPrivateKeySpec(d, parameters));
        byte[] material = KeyMaterialCodec.encodeKeyPair(privateKey.getEncoded(),
                publicKey.getEncoded());
        return new ImportedMaterial(KeyMaterialCodec.KEYPAIR, material,
                parameters.getCurve().getField().getFieldSize());
    }

    private static ECParameterSpec ecParameters(String name) throws GeneralSecurityException {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(name));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException first) {
            if (java.security.Security.getProvider("BC") != null) {
                AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "BC");
                parameters.init(new ECGenParameterSpec(name));
                return parameters.getParameterSpec(ECParameterSpec.class);
            }
            throw first;
        }
    }

    private static void validateSymmetricLength(KeyType type, int length) {
        if (length == 0) {
            throw importFailure("Imported key material is empty");
        }
        if (length > KeyRecordCodec.MAX_MATERIAL_BYTES) {
            throw new KeyException(ErrorCode.INVALID_PARAMETER,
                    "Imported key material exceeds the maximum supported size");
        }
        int bits = length * 8;
        if (type == KeyType.AES && bits != 128 && bits != 192 && bits != 256) {
            throw new KeyException(ErrorCode.MIN_KEY_BITS_VIOLATION,
                    "AES keys must be 128, 192 or 256 bits");
        }
        if (type == KeyType.SM4 && bits != 128) {
            throw new KeyException(ErrorCode.MIN_KEY_BITS_VIOLATION, "SM4 keys must be 128 bits");
        }
    }

    private static int keyBits(Key key, KeyType type) {
        return switch (type) {
            case RSA -> ((RSAKey) key).getModulus().bitLength();
            case EC, SM2 -> ((ECKey) key).getParams().getCurve().getField().getFieldSize();
            case ED25519 -> 256;
            case ED448 -> 456;
            case AES, SM4, HMAC, SYMMETRIC, RAW, KEM -> {
                byte[] encoded = key.getEncoded();
                yield encoded == null ? 0 : encoded.length * 8;
            }
        };
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isTextual() || value.asText().isBlank()) {
            throw importFailure("JWK is missing a required field");
        }
        return value.asText();
    }

    private static byte[] base64Url(String value) {
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw importFailure("JWK contains invalid Base64Url data");
        }
    }

    private static KeyException importFailure(String message) {
        return new KeyException(ErrorCode.KEY_IMPORT_FAILED, message);
    }

    /** Canonical material produced by an import. */
    public record ImportedMaterial(String materialFormat, byte[] material, int keyBits) {
        public ImportedMaterial {
            if (!KeyMaterialCodec.isKnownMaterialFormat(materialFormat)) {
                throw new IllegalArgumentException("Unknown material format");
            }
            material = material.clone();
            if (material.length == 0) {
                throw new IllegalArgumentException("Imported material must not be empty");
            }
            if (keyBits < 0) {
                throw new IllegalArgumentException("keyBits must not be negative");
            }
        }

        @Override
        public byte[] material() {
            return material.clone();
        }
    }
}