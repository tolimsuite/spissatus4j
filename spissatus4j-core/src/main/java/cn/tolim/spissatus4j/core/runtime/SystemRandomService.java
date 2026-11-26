package cn.tolim.spissatus4j.core.runtime;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.crypto.RandomService;
import cn.tolim.spissatus4j.contract.crypto.Salt;
import cn.tolim.spissatus4j.contract.exception.CryptoException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;

/**
 * JDK CSPRNG backed randomness service used when no crypto module is present.
 * The crypto module contributes its own instance; this class keeps the core
 * usable (and fail-closed) on its own.
 */
public final class SystemRandomService implements RandomService {

    private static final int MAX_REQUEST = 1024 * 1024;

    private final SecureRandom random;

    public SystemRandomService() {
        this.random = new SecureRandom();
    }

    @Override
    public byte[] nextBytes(int length) {
        if (length < 0 || length > MAX_REQUEST) {
            throw new IllegalArgumentException("Invalid random byte length");
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
        return new UUID(most, least);
    }

    @Override
    public Nonce nextNonce(AlgorithmId algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        int length = algorithm.info().nonceBytes();
        if (length <= 0 || length > 64) {
            throw new CryptoException(ErrorCode.NONCE_INVALID,
                    "Algorithm does not define a usable nonce length: " + algorithm.id());
        }
        return Nonce.of(nextBytes(length));
    }

    @Override
    public Salt nextSalt(int byteLength) {
        if (byteLength < 1 || byteLength > 256) {
            throw new IllegalArgumentException("Invalid salt length");
        }
        return Salt.of(nextBytes(byteLength));
    }

    @Override
    public HealthStatus health() {
        try {
            byte[] first = nextBytes(32);
            byte[] second = nextBytes(32);
            boolean ok = !Arrays.equals(first, second);
            Arrays.fill(first, (byte) 0);
            Arrays.fill(second, (byte) 0);
            return ok ? HealthStatus.UP : HealthStatus.DOWN;
        } catch (RuntimeException e) {
            return HealthStatus.DOWN;
        }
    }
}