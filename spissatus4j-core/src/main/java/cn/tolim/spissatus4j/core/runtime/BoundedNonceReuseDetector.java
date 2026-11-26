package cn.tolim.spissatus4j.core.runtime;

import cn.tolim.spissatus4j.contract.algorithm.AlgorithmId;
import cn.tolim.spissatus4j.contract.crypto.Nonce;
import cn.tolim.spissatus4j.contract.runtime.HealthStatus;
import cn.tolim.spissatus4j.contract.runtime.NonceReuseDetector;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Bounded in-memory nonce registry with age-based expiry.
 *
 * <p>Eviction of the oldest entry is a deliberate trade-off between memory
 * and detection window; configure the capacity to cover the maximum number of
 * encryptions expected within the TTL. A storage failure must be treated as
 * fail-closed by the caller.</p>
 */
public final class BoundedNonceReuseDetector implements NonceReuseDetector {

    private final int maxEntries;
    private final Duration ttl;
    private final Clock clock;
    private final LinkedHashMap<String, Instant> seen =
            new LinkedHashMap<>(1024, 0.75f, true);

    public BoundedNonceReuseDetector(int maxEntries, Duration ttl, Clock clock) {
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be positive");
        }
        this.maxEntries = maxEntries;
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public BoundedNonceReuseDetector() {
        this(1_000_000, Duration.ofHours(24), Clock.systemUTC());
    }

    @Override
    public synchronized boolean register(AlgorithmId algorithm, Nonce nonce) {
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(nonce, "nonce");
        if (nonce.isEmpty()) {
            return false;
        }
        Instant now = clock.instant();
        purgeExpired(now);
        String key = algorithm.id() + "|" + Base64.getEncoder().encodeToString(nonce.asBytes());
        Instant previous = seen.put(key, now);
        if (previous != null) {
            seen.put(key, previous);
            return true;
        }
        while (seen.size() > maxEntries) {
            Iterator<Map.Entry<String, Instant>> iterator = seen.entrySet().iterator();
            if (iterator.hasNext()) {
                iterator.next();
                iterator.remove();
            }
        }
        return false;
    }

    private void purgeExpired(Instant now) {
        seen.entrySet().removeIf(entry -> entry.getValue().plus(ttl).isBefore(now));
    }

    @Override
    public synchronized void clear() {
        seen.clear();
    }

    @Override
    public HealthStatus health() {
        return HealthStatus.UP;
    }

    @Override
    public synchronized int size() {
        return seen.size();
    }
}