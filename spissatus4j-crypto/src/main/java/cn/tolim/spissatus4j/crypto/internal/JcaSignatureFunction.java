package cn.tolim.spissatus4j.crypto.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.SignatureFunction;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAKey;
import java.security.spec.PSSParameterSpec;
import java.util.Objects;

/** JCA signature engine for EdDSA, ECDSA (P1363) and RSA-PSS. */
final class JcaSignatureFunction implements SignatureFunction {

    private static final int MIN_RSA_BITS = 2048;

    private final AlgorithmId algorithm;
    private final String jcaName;
    private final PSSParameterSpec pssParameters;

    JcaSignatureFunction(AlgorithmId algorithm, String jcaName, PSSParameterSpec pssParameters) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.jcaName = Objects.requireNonNull(jcaName, "jcaName");
        this.pssParameters = pssParameters;
    }

    @Override
    public AlgorithmId algorithm() {
        return algorithm;
    }

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] message) {
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(message, "message");
        requireRsaKeySize(privateKey);
        try {
            Signature signature = newSignature();
            signature.initSign(privateKey);
            signature.update(message);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE, "Signing failed", e);
        }
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] message, byte[] signatureBytes) {
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(signatureBytes, "signature");
        requireRsaKeySize(publicKey);
        try {
            Signature signature = newSignature();
            signature.initVerify(publicKey);
            signature.update(message);
            return signature.verify(signatureBytes);
        } catch (SignatureException e) {
            // Malformed signature encodings are simply invalid signatures.
            return false;
        } catch (InvalidKeyException e) {
            throw new CryptoException(ErrorCode.SIGNATURE_VERIFICATION_FAILED,
                    "Signature verification failed", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(ErrorCode.PROVIDER_FAILURE,
                    "Signature verification failed", e);
        }
    }

    private Signature newSignature() throws GeneralSecurityException {
        Signature signature = Signature.getInstance(jcaName);
        if (pssParameters != null) {
            signature.setParameter(pssParameters);
        }
        return signature;
    }

    private void requireRsaKeySize(java.security.Key key) {
        if (key instanceof RSAKey rsaKey && rsaKey.getModulus().bitLength() < MIN_RSA_BITS) {
            throw new CryptoException(ErrorCode.MIN_KEY_BITS_VIOLATION,
                    "RSA keys must be at least " + MIN_RSA_BITS + " bits");
        }
    }
}
