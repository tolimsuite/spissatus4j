package cn.tolim.spissatus4j.crypto.random;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.RandomService;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;

/**
 * CSPRNG-backed randomness service. Uses the strongest platform
 * {@link SecureRandom} available and never exposes a deterministic PRNG.
 */
public final class SecureRandomService implements RandomService {

    private static final int MAX_REQUEST_BYTES = 1024 * 1024;
    private static final int MAX_NONCE_BYTES = 64;
    private static final int MAX_SALT_BYTES = 256;

    private final SecureRandom random;

    public SecureRandomService() {
        this.random = createStrongRandom();
    }

    private static SecureRandom createStrongRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            // Every conforming JDK ships a default strong algorithm; fall back
            // defensively rather than failing module startup.
            return new SecureRandom();
        }
    }

    @Override
    public byte[] nextBytes(int length) {
        if (length < 0 || length > MAX_REQUEST_BYTES) {
            throw new IllegalArgumentException("Random request must be between 0 and 1 MiB");
        }
        byte[] result = new byte[length];
        random.nextBytes(result);
        return result;
    }

    @Override
    public String nextBase64(int byteLength) {
        return Base64.getEncoder().encodeToString(nextBytes(byteLength));
    }

    @Override
    public String nextUrlSafeToken(int byteLength) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(nextBytes(byteLength));
    }

    @Override
    public UUID nextUuid() {
        byte[] value = nextBytes(16);
        value[6] = (byte) ((value[6] & 0x0f) | 0x40);
        value[8] = (byte) ((value[8] & 0x3f) | 0x80);
        long most = 0;
        long least = 0;
        for (int i = 0; i < 8; i++) {
            most = (most << 8) | (value[i] & 0xffL);
            least = (least << 8) | (value[i + 8] & 0xffL);
        }
        Arrays.fill(value, (byte) 0);
        return new UUID(most, least);
    }

    @Override
    public Nonce nextNonce(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        int length = algorithm.info().nonceBytes();
        if (length <= 0 || length > MAX_NONCE_BYTES) {
            throw new CryptoException(ErrorCode.NONCE_INVALID,
                    "Algorithm does not define a usable nonce length: " + algorithm.id());
        }
        return Nonce.of(nextBytes(length));
    }

    @Override
    public Salt nextSalt(int byteLength) {
        if (byteLength < 1 || byteLength > MAX_SALT_BYTES) {
            throw new IllegalArgumentException("Salt length must be between 1 and 256 bytes");
        }
        return Salt.of(nextBytes(byteLength));
    }

    @Override
    public HealthStatus health() {
        byte[] first = null;
        byte[] second = null;
        try {
            first = nextBytes(32);
            second = nextBytes(32);
            boolean distinct = !Arrays.equals(first, second);
            boolean nonZero = false;
            for (byte value : first) {
                if (value != 0) {
                    nonZero = true;
                    break;
                }
            }
            return distinct && nonZero ? HealthStatus.UP : HealthStatus.DOWN;
        } catch (RuntimeException e) {
            return HealthStatus.DOWN;
        } finally {
            if (first != null) {
                Arrays.fill(first, (byte) 0);
            }
            if (second != null) {
                Arrays.fill(second, (byte) 0);
            }
        }
    }
}
