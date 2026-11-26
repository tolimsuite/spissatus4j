package cn.tolim.spissatus4j.bc.internal;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.HashFunction;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Objects;

/**
 * Stateless digest engine backed by the configured JCA provider.
 *
 * <p>Every digest, including SHAKE128/SHAKE256 (fixed-output JCA names
 * {@code SHAKE128-256} and {@code SHAKE256-512}) and BLAKE2b, is obtained
 * through {@link MessageDigest#getInstance(String, Provider)} with the
 * provider supplied to the algorithm provider. No Bouncy Castle lightweight
 * digest is constructed directly, so a FIPS deployment can never route a
 * digest outside its validated provider: when the configured provider does
 * not register the algorithm the call fails with a provider failure instead
 * of silently falling back. Engines are thread-safe because a fresh digest
 * is created for every operation.</p>
 *
 * <p>Internal type; not part of the public API.</p>
 */
public final class BcHashFunction implements HashFunction {

    private static final int STREAM_BUFFER = 8192;

    private final AlgorithmId algorithm;
    private final int digestLength;
    private final String jcaName;
    private final Provider provider;

    /** Creates a digest engine over the configured JCA provider. */
    public BcHashFunction(AlgorithmId algorithm, int digestLength, String jcaName, Provider provider) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.digestLength = digestLength;
        this.jcaName = Objects.requireNonNull(jcaName, "jcaName");
        this.provider = Objects.requireNonNull(provider, "provider");
        if (digestLength < 1) {
            throw BcProviders.invalidParameter("Invalid digest length");
        }
    }

    @Override
    public AlgorithmId algorithm() {
        return algorithm;
    }

    @Override
    public int digestLength() {
        return digestLength;
    }

    @Override
    public byte[] digest(byte[] data) {
        Objects.requireNonNull(data, "data");
        return checked(messageDigest().digest(data));
    }

    @Override
    public byte[] digest(InputStream input) throws IOException {
        Objects.requireNonNull(input, "input");
        MessageDigest digest = messageDigest();
        byte[] buffer = new byte[STREAM_BUFFER];
        int read;
        while ((read = input.read(buffer)) != -1) {
            if (read > 0) {
                digest.update(buffer, 0, read);
            }
        }
        return checked(digest.digest());
    }

    /** Rejects a provider that produced a digest of the wrong length. */
    private byte[] checked(byte[] result) {
        if (result.length != digestLength) {
            BcProviders.clear(result);
            throw BcProviders.providerFailure("Digest produced an unexpected length");
        }
        return result;
    }

    private MessageDigest messageDigest() {
        try {
            return MessageDigest.getInstance(jcaName, provider);
        } catch (NoSuchAlgorithmException e) {
            throw BcProviders.providerFailure("Digest algorithm is unavailable");
        }
    }
}