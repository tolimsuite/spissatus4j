package cn.tolim.spissatus4j.gm.sm2;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.SignatureFunction;
import cn.tolim.spissatus4j.gm.internal.BcKeyConversion;
import cn.tolim.spissatus4j.gm.internal.Sm2Operations;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * SM2 digital signature with SM3, DER-encoded signatures and the GB/T 32918
 * default user identifier {@code 1234567812345678}.
 */
public final class Sm2Signature implements SignatureFunction {

    private final SecureRandom random;

    public Sm2Signature() {
        this.random = new SecureRandom();
    }

    @Override
    public AlgorithmId algorithm() {
        return AlgorithmId.SM2_SIGNATURE;
    }

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] message) {
        return Sm2Operations.sign(BcKeyConversion.toPrivateKeyParameters(privateKey), message, random);
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] message, byte[] signature) {
        return Sm2Operations.verify(BcKeyConversion.toPublicKeyParameters(publicKey), message, signature);
    }
}