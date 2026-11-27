package cn.tolim.spissatus4j.contract.facade;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.DecryptRequest;
import cn.tolim.spissatus4j.contract.crypto.DerivedKey;
import cn.tolim.spissatus4j.contract.crypto.DigestRequest;
import cn.tolim.spissatus4j.contract.crypto.EncryptRequest;
import cn.tolim.spissatus4j.contract.crypto.EncryptedData;
import cn.tolim.spissatus4j.contract.crypto.KdfRequest;
import cn.tolim.spissatus4j.contract.crypto.MacRequest;
import cn.tolim.spissatus4j.contract.crypto.MacVerifyRequest;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.SignRequest;
import cn.tolim.spissatus4j.contract.crypto.StreamEncryptRequest;
import cn.tolim.spissatus4j.contract.crypto.VerifyRequest;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Unified cryptographic operations facade. Every operation is policy-checked,
 * fail-closed, nonce-tracked and audited.
 */
public interface CryptoService {

    EncryptedData encrypt(EncryptRequest request);

    byte[] decrypt(DecryptRequest request);

    byte[] sign(SignRequest request);

    boolean verify(VerifyRequest request);

    byte[] digest(DigestRequest request);

    byte[] mac(MacRequest request);

    boolean verifyMac(MacVerifyRequest request);

    DerivedKey deriveKey(KdfRequest request);

    byte[] randomBytes(int length);

    Nonce randomNonce(AlgorithmId algorithm);

    OutputStream openEncryptingStream(OutputStream output, StreamEncryptRequest request) throws IOException;

    InputStream openDecryptingStream(InputStream input, CallerContext caller) throws IOException;

    /**
     * Resume support: skips {@code chunksToSkip} frames before decrypting.
     * Skipping is unauthenticated but each subsequent chunk is authenticated
     * against its absolute index, so a wrong offset is detected.
     */
    InputStream openDecryptingStream(InputStream input, CallerContext caller, long chunksToSkip)
            throws IOException;
}