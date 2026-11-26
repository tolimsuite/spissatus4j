package cn.tolim.spissatus4j.bc.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.MacFunction;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * HMAC engine backed by the Bouncy Castle JCA provider. Verification uses a
 * constant-time comparison and never reveals the expected or computed tag.
 *
 * <p>Internal type; not part of the public API.</p>
 */
public final class BcMacFunction implements MacFunction {

    private static final int STREAM_BUFFER = 8192;

    private final AlgorithmId algorithm;
    private final int tagLength;
    private final String jcaName;
    private final Provider provider;

    public BcMacFunction(AlgorithmId algorithm, int tagLength, String jcaName, Provider provider) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.tagLength = tagLength;
        this.jcaName = Objects.requireNonNull(jcaName, "jcaName");
        this.provider = Objects.requireNonNull(provider, "provider");
    }

    @Override
    public AlgorithmId algorithm() {
        return algorithm;
    }

    @Override
    public int tagLength() {
        return tagLength;
    }

    @Override
    public byte[] compute(SecretKey key, byte[] data) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(data, "data");
        try {
            Mac mac = Mac.getInstance(jcaName, provider);
            mac.init(key);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw BcProviders.providerFailure("MAC algorithm is unavailable");
        } catch (InvalidKeyException e) {
            throw BcProviders.invalidParameter("Invalid MAC key");
        }
    }

    @Override
    public byte[] compute(SecretKey key, InputStream input) throws IOException {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(input, "input");
        try {
            Mac mac = Mac.getInstance(jcaName, provider);
            mac.init(key);
            byte[] buffer = new byte[STREAM_BUFFER];
            int read;
            while ((read = input.read(buffer)) != -1) {
                if (read > 0) {
                    mac.update(buffer, 0, read);
                }
            }
            return mac.doFinal();
        } catch (NoSuchAlgorithmException e) {
            throw BcProviders.providerFailure("MAC algorithm is unavailable");
        } catch (InvalidKeyException e) {
            throw BcProviders.invalidParameter("Invalid MAC key");
        }
    }

    @Override
    public boolean verify(SecretKey key, byte[] data, byte[] expectedTag) {
        Objects.requireNonNull(expectedTag, "expectedTag");
        byte[] actualTag = compute(key, data);
        try {
            return MessageDigest.isEqual(actualTag, expectedTag);
        } finally {
            Arrays.fill(actualTag, (byte) 0);
        }
    }
}