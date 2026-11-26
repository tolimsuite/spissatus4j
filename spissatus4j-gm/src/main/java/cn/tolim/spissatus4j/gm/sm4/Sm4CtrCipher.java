package cn.tolim.spissatus4j.gm.sm4;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.AAD;
import cn.tolim.spissatus4j.contract.crypto.AeadCipher;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.gm.internal.Sm4Etm;
import javax.crypto.SecretKey;

/**
 * SM4-CTR, wrapped in Encrypt-then-MAC with HMAC-SM3. The 16-byte nonce is
 * the initial counter block; the 32-byte tag authenticates the algorithm,
 * nonce, AAD and ciphertext.
 */
public final class Sm4CtrCipher implements AeadCipher {

    @Override
    public AlgorithmId algorithm() {
        return AlgorithmId.SM4_CTR;
    }

    @Override
    public int nonceLength() {
        return Sm4Etm.NONCE_LENGTH;
    }

    @Override
    public int tagLength() {
        return Sm4Etm.TAG_LENGTH;
    }

    @Override
    public AeadResult encrypt(SecretKey key, byte[] plaintext, Nonce nonce, AAD aad) {
        return Sm4Etm.encrypt(AlgorithmId.SM4_CTR, Sm4Etm.Mode.CTR, key, plaintext, nonce, aad);
    }

    @Override
    public byte[] decrypt(SecretKey key, Nonce nonce, byte[] ciphertext, byte[] tag, AAD aad) {
        return Sm4Etm.decrypt(AlgorithmId.SM4_CTR, Sm4Etm.Mode.CTR, key, nonce, ciphertext, tag, aad);
    }
}