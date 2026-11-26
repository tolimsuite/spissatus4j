package cn.tolim.spissatus4j.gm.internal;

import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Converts between JCA key objects and Bouncy Castle lightweight EC key
 * parameters for the SM2 curve, and generates SM2 key pairs without requiring
 * a globally registered JCA provider.
 *
 * <p>Only keys on {@code sm2p256v1} are accepted; every other curve is
 * rejected with a generic parameter error.</p>
 */
public final class BcKeyConversion {

    public static final String SM2_CURVE_NAME = "sm2p256v1";
    public static final ASN1ObjectIdentifier SM2_CURVE_OID = GMNamedCurves.getOID(SM2_CURVE_NAME);

    private static final X9ECParameters SM2_CURVE = GMNamedCurves.getByName(SM2_CURVE_NAME);
    public static final ECDomainParameters SM2_DOMAIN =
            new ECNamedDomainParameters(SM2_CURVE_OID, SM2_CURVE);

    private BcKeyConversion() {
    }

    /** Converts a JCA public key into validated SM2 lightweight parameters. */
    public static ECPublicKeyParameters toPublicKeyParameters(PublicKey publicKey) {
        if (publicKey == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "A public key is required");
        }
        byte[] encoded;
        try {
            encoded = publicKey.getEncoded();
        } catch (RuntimeException e) {
            throw invalidKey();
        }
        if (encoded == null || encoded.length == 0) {
            throw invalidKey();
        }
        try {
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(encoded);
            AsymmetricKeyParameter parameters = PublicKeyFactory.createKey(subjectPublicKeyInfo);
            if (!(parameters instanceof ECPublicKeyParameters ecPublicKey)) {
                throw invalidKey();
            }
            requireSm2Domain(ecPublicKey.getParameters());
            ECPoint point = ecPublicKey.getQ();
            if (point == null || point.isInfinity() || !point.isValid()) {
                throw invalidKey();
            }
            return ecPublicKey;
        } catch (CryptoException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            throw invalidKey();
        }
    }

    /** Converts a JCA private key into validated SM2 lightweight parameters. */
    public static ECPrivateKeyParameters toPrivateKeyParameters(PrivateKey privateKey) {
        if (privateKey == null) {
            throw new CryptoException(ErrorCode.INVALID_PARAMETER, "A private key is required");
        }
        byte[] encoded;
        try {
            encoded = privateKey.getEncoded();
        } catch (RuntimeException e) {
            throw invalidKey();
        }
        if (encoded == null || encoded.length == 0) {
            throw invalidKey();
        }
        try {
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(encoded);
            AsymmetricKeyParameter parameters = PrivateKeyFactory.createKey(privateKeyInfo);
            if (!(parameters instanceof ECPrivateKeyParameters ecPrivateKey)) {
                throw invalidKey();
            }
            requireSm2Domain(ecPrivateKey.getParameters());
            BigInteger scalar = ecPrivateKey.getD();
            if (scalar == null || scalar.signum() <= 0 || scalar.compareTo(SM2_CURVE.getN()) >= 0) {
                throw invalidKey();
            }
            return ecPrivateKey;
        } catch (CryptoException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            throw invalidKey();
        }
    }

    /** Encodes lightweight SM2 public parameters as a JCA public key. */
    public static PublicKey toJcaPublicKey(ECPublicKeyParameters publicKey) {
        if (publicKey == null) {
            throw invalidKey();
        }
        try {
            SubjectPublicKeyInfo subjectPublicKeyInfo =
                    SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", BcProviderHolder.INSTANCE);
            return keyFactory.generatePublic(new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded()));
        } catch (IOException | GeneralSecurityException e) {
            throw invalidKey();
        }
    }

    /** Encodes lightweight SM2 private parameters as a JCA private key. */
    public static PrivateKey toJcaPrivateKey(ECPrivateKeyParameters privateKey) {
        if (privateKey == null) {
            throw invalidKey();
        }
        try {
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", BcProviderHolder.INSTANCE);
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
        } catch (IOException | GeneralSecurityException e) {
            throw invalidKey();
        }
    }

    /** Generates an SM2 key pair using the lightweight BC API. */
    public static AsymmetricCipherKeyPair generateKeyPair(SecureRandom random) {
        Objects.requireNonNull(random, "random");
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(SM2_DOMAIN, random));
        return generator.generateKeyPair();
    }

    /** Rejects any domain parameters that are not exactly the SM2 named curve. */
    public static void requireSm2Domain(ECDomainParameters parameters) {
        if (!isSm2Domain(parameters)) {
            throw invalidKey();
        }
    }

    /** Returns whether the given parameters denote the SM2 named curve. */
    public static boolean isSm2Domain(ECDomainParameters parameters) {
        return parameters != null
                && SM2_CURVE.getCurve().equals(parameters.getCurve())
                && SM2_CURVE.getG().equals(parameters.getG())
                && SM2_CURVE.getN().equals(parameters.getN())
                && SM2_CURVE.getH().equals(parameters.getH());
    }

    private static CryptoException invalidKey() {
        return new CryptoException(ErrorCode.INVALID_PARAMETER,
                "Key is not an SM2 key on the sm2p256v1 curve");
    }

    private static final class BcProviderHolder {
        private static final BouncyCastleProvider INSTANCE = new BouncyCastleProvider();

        private BcProviderHolder() {
        }
    }
}