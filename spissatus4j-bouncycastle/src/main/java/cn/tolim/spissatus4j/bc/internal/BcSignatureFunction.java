package cn.tolim.spissatus4j.bc.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.SignatureFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

/**
 * Signature engine backed by the Bouncy Castle JCA provider.
 *
 * <p>Ed448 uses the RFC 8032 scheme, ECDSA uses the fixed-width IEEE P1363
 * encoding (not DER) and RSA-PSS uses SHA-256 with MGF1-SHA-256 and a
 * 32-byte salt. Verification failures return {@code false}; invalid inputs
 * and provider failures raise the sealed contract exceptions.</p>
 *
 * <p>Internal type; not part of the public API.</p>
 */
public final class BcSignatureFunction implements SignatureFunction {

    private final AlgorithmId algorithm;
    private final String jcaName;
    private final Provider provider;
    private final AlgorithmParameterSpec parameterSpec;

    public BcSignatureFunction(AlgorithmId algorithm, String jcaName, Provider provider) {
        this(algorithm, jcaName, provider, null);
    }

    public BcSignatureFunction(AlgorithmId algorithm, String jcaName, Provider provider,
                               AlgorithmParameterSpec parameterSpec) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.jcaName = Objects.requireNonNull(jcaName, "jcaName");
        this.provider = Objects.requireNonNull(provider, "provider");
        this.parameterSpec = parameterSpec;
    }

    @Override
    public AlgorithmId algorithm() {
        return algorithm;
    }

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] message) {
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(message, "message");
        enforceRsaMinimum(privateKey);
        try {
            Signature signature = newSignature();
            signature.initSign(privateKey);
            signature.update(message);
            return signature.sign();
        } catch (NoSuchAlgorithmException e) {
            throw BcProviders.providerFailure("Signature algorithm is unavailable");
        } catch (InvalidAlgorithmParameterException e) {
            throw BcProviders.providerFailure("Signature parameters are not supported");
        } catch (InvalidKeyException e) {
            throw BcProviders.invalidParameter("Invalid private key for signature");
        } catch (SignatureException e) {
            throw BcProviders.providerFailure("Signature generation failed");
        }
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] message, byte[] signature) {
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(signature, "signature");
        enforceRsaMinimum(publicKey);
        try {
            Signature verifier = newSignature();
            verifier.initVerify(publicKey);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            throw BcProviders.providerFailure("Signature algorithm is unavailable");
        } catch (InvalidAlgorithmParameterException e) {
            throw BcProviders.providerFailure("Signature parameters are not supported");
        } catch (InvalidKeyException e) {
            throw BcProviders.invalidParameter("Invalid public key for signature");
        } catch (SignatureException e) {
            return false;
        }
    }

    private static void enforceRsaMinimum(java.security.Key key) {
        if (key instanceof RSAKey rsa) {
            int bits = rsa.getModulus().bitLength();
            if (bits < 2048) {
                throw new CryptoException(
                        cn.tolim.spissatus4j.contract.exception.ErrorCode.MIN_KEY_BITS_VIOLATION,
                        "RSA signature keys must be at least 2048 bits");
            }
        }
    }

    private Signature newSignature() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance(jcaName, provider);
        if (parameterSpec != null) {
            signature.setParameter(parameterSpec);
        }
        return signature;
    }
}