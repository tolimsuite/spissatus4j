package cn.tolim.spissatus4j.policy.access;

import cn.tolim.spissatus4j.contract.policy.AccessPolicy;
import cn.tolim.spissatus4j.contract.policy.CallerContext;
import cn.tolim.spissatus4j.contract.policy.PolicyDecision;
import cn.tolim.spissatus4j.contract.policy.PolicyRequest;
import cn.tolim.spissatus4j.contract.policy.ReasonCodes;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Default caller access policy: deny-by-default authentication, caller
 * allow-list, required role, deployment environment, per-caller token-bucket
 * rate limiting and per-tenant quota.
 *
 * <p>Both limits are expressed per minute. A limit of {@code 0} disables the
 * corresponding check. Buckets start full and refill continuously at the
 * configured rate; time is read from the supplied {@link Clock} so tests can
 * move time deterministically.</p>
 *
 * <p>Rate-limit buckets are scoped to a {@code (tenantId, callerId)} pair, so
 * the same caller identity in different tenants is limited independently, and
 * tenant quotas remain scoped to the tenant. Bucket state is bounded: buckets
 * idle for at least {@link #BUCKET_RETENTION_MILLIS} (which is long enough for
 * a bucket to refill completely) are evicted, and the map never tracks more
 * than {@link #MAX_TRACKED_BUCKETS} entries, dropping the least recently used
 * ones if a deployment exceeds that many active identities.</p>
 */
public final class DefaultAccessPolicy implements AccessPolicy {

    /** Stable, non-sensitive policy identifier. */
    public static final String RULE_ID = "access";

    private static final double MILLIS_PER_MINUTE = 60_000.0;
    private static final double EPSILON = 1e-9;

    /**
     * Idle buckets are evicted after max(2 minutes, 2 rate windows); both rate
     * windows are one minute, so a bucket idle this long has refilled fully.
     */
    public static final long BUCKET_RETENTION_MILLIS = 120_000L;

    /** Hard bound on tracked rate-limit/quota buckets to keep memory bounded. */
    public static final int MAX_TRACKED_BUCKETS = 1_024;

    private final boolean allowAnonymous;
    private final Set<String> allowedCallers;
    private final String requiredRole;
    private final Set<String> allowedEnvironments;
    private final int rateLimitPerMinute;
    private final int tenantQuotaPerMinute;
    private final Clock clock;
    private final ConcurrentMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    /**
     * Creates the default policy: anonymous callers are denied, any
     * authenticated caller is accepted, no role or environment restriction is
     * applied, and rate limiting and quotas are disabled.
     */
    public DefaultAccessPolicy() {
        this(false, Set.of(), "", Set.of(), 0, 0, Clock.systemUTC());
    }

    /**
     * Creates the default policy with a custom clock.
     *
     * @param clock clock used for rate-limit refill and tenant quotas
     */
    public DefaultAccessPolicy(Clock clock) {
        this(false, Set.of(), "", Set.of(), 0, 0, clock);
    }

    /**
     * Creates a policy without a tenant quota.
     *
     * @param allowAnonymous whether anonymous callers are allowed
     * @param allowedCallers caller-id allow-list; empty accepts any authenticated caller
     * @param requiredRole role every caller must carry; empty disables the check
     * @param allowedEnvironments allowed deployment environments; empty accepts any
     * @param rateLimitPerMinute per-caller requests per minute; {@code 0} disables
     * @param clock clock used for rate-limit refill
     */
    public DefaultAccessPolicy(boolean allowAnonymous,
                               Set<String> allowedCallers,
                               String requiredRole,
                               Set<String> allowedEnvironments,
                               int rateLimitPerMinute,
                               Clock clock) {
        this(allowAnonymous, allowedCallers, requiredRole, allowedEnvironments,
                rateLimitPerMinute, 0, clock);
    }

    /**
     * Creates a fully configured policy.
     *
     * @param allowAnonymous whether anonymous callers are allowed
     * @param allowedCallers caller-id allow-list; empty accepts any authenticated caller
     * @param requiredRole role every caller must carry; empty disables the check
     * @param allowedEnvironments allowed deployment environments; empty accepts any
     * @param rateLimitPerMinute per-caller requests per minute; {@code 0} disables
     * @param tenantQuotaPerMinute per-tenant requests per minute; {@code 0} disables
     * @param clock clock used for refill and quota accounting
     * @throws IllegalArgumentException if a limit is negative
     */
    public DefaultAccessPolicy(boolean allowAnonymous,
                               Set<String> allowedCallers,
                               String requiredRole,
                               Set<String> allowedEnvironments,
                               int rateLimitPerMinute,
                               int tenantQuotaPerMinute,
                               Clock clock) {
        this.allowAnonymous = allowAnonymous;
        this.allowedCallers = copyNames(allowedCallers);
        this.requiredRole = requiredRole == null ? "" : requiredRole.trim();
        this.allowedEnvironments = copyNames(allowedEnvironments);
        if (rateLimitPerMinute < 0) {
            throw new IllegalArgumentException("rateLimitPerMinute must not be negative");
        }
        if (tenantQuotaPerMinute < 0) {
            throw new IllegalArgumentException("tenantQuotaPerMinute must not be negative");
        }
        this.rateLimitPerMinute = rateLimitPerMinute;
        this.tenantQuotaPerMinute = tenantQuotaPerMinute;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    public boolean allowAnonymous() {
        return allowAnonymous;
    }

    public Set<String> allowedCallers() {
        return allowedCallers;
    }

    public String requiredRole() {
        return requiredRole;
    }

    public Set<String> allowedEnvironments() {
        return allowedEnvironments;
    }

    public int rateLimitPerMinute() {
        return rateLimitPerMinute;
    }

    public int tenantQuotaPerMinute() {
        return tenantQuotaPerMinute;
    }

    @Override
    public PolicyDecision evaluate(PolicyRequest request) {
        if (request == null) {
            return PolicyDecision.deny(ReasonCodes.POLICY_UNAVAILABLE,
                    "No policy request available", RULE_ID);
        }
        CallerContext caller = request.caller();
        if (caller == null) {
            return PolicyDecision.deny(ReasonCodes.POLICY_UNAVAILABLE,
                    "No caller identity available", RULE_ID);
        }
        if (caller.isAnonymous() && !allowAnonymous) {
            return PolicyDecision.deny(ReasonCodes.ANONYMOUS_CALLER,
                    "Anonymous callers are not allowed", RULE_ID);
        }
        if (!allowedCallers.isEmpty() && !allowedCallers.contains(caller.callerId())) {
            return PolicyDecision.deny(ReasonCodes.CALLER_NOT_AUTHORIZED,
                    "Caller is not authorized", RULE_ID);
        }
        if (!requiredRole.isEmpty() && !caller.hasRole(requiredRole)) {
            return PolicyDecision.deny(ReasonCodes.CALLER_NOT_AUTHORIZED,
                    "Caller does not carry the required role", RULE_ID);
        }
        if (!allowedEnvironments.isEmpty() && !allowedEnvironments.contains(caller.environment())) {
            return PolicyDecision.deny(ReasonCodes.CALLER_NOT_AUTHORIZED,
                    "Caller environment is not allowed", RULE_ID);
        }
        if (rateLimitPerMinute > 0
                && !acquire(callerBucketKey(caller), rateLimitPerMinute)) {
            return PolicyDecision.deny(ReasonCodes.RATE_LIMITED,
                    "Caller rate limit exceeded", RULE_ID);
        }
        if (tenantQuotaPerMinute > 0
                && !acquire(tenantBucketKey(caller), tenantQuotaPerMinute)) {
            return PolicyDecision.deny(ReasonCodes.QUOTA_EXCEEDED,
                    "Tenant quota exceeded", RULE_ID);
        }
        return PolicyDecision.allow(RULE_ID);
    }

    /** Number of rate-limit and quota buckets currently tracked; diagnostic hook. */
    public int trackedBucketCount() {
        return buckets.size();
    }

    private static String callerBucketKey(CallerContext caller) {
        return "caller\u0000" + caller.tenantId() + "\u0000" + caller.callerId();
    }

    private static String tenantBucketKey(CallerContext caller) {
        return "tenant\u0000" + caller.tenantId();
    }

    private boolean acquire(String key, int limitPerMinute) {
        long nowMillis = clock.millis();
        boolean existing = buckets.containsKey(key);
        evictBuckets(nowMillis, existing ? 0 : 1, key);
        TokenBucket bucket = buckets.computeIfAbsent(key,
                ignored -> new TokenBucket(limitPerMinute, nowMillis));
        synchronized (bucket) {
            bucket.lastAccessMillis = nowMillis;
            long elapsed = nowMillis - bucket.lastRefillMillis;
            if (elapsed > 0) {
                bucket.tokens = Math.min(bucket.capacity,
                        bucket.tokens + elapsed * (bucket.capacity / MILLIS_PER_MINUTE));
                bucket.lastRefillMillis = nowMillis;
            }
            if (bucket.tokens + EPSILON >= 1.0d) {
                bucket.tokens -= 1.0d;
                return true;
            }
            return false;
        }
    }

    /**
     * Evicts buckets that have been idle long enough to refill completely and
     * enforces the hard map bound by dropping least recently used buckets.
     * A dropped bucket restarts full, which is exactly the state an idle bucket
     * of that age would have reached anyway.
     */
    private void evictBuckets(long nowMillis, int slotsToReserve, String protectedKey) {
        if (buckets.isEmpty()) {
            return;
        }
        for (Map.Entry<String, TokenBucket> entry : buckets.entrySet()) {
            if (entry.getKey().equals(protectedKey)) {
                continue;
            }
            long idleMillis = nowMillis - entry.getValue().lastAccessMillis;
            if (idleMillis >= BUCKET_RETENTION_MILLIS) {
                buckets.remove(entry.getKey(), entry.getValue());
            }
        }
        // Reserve a slot only when a new bucket is about to be inserted, and never
        // evict the bucket that is currently being charged.
        int excess = buckets.size() - MAX_TRACKED_BUCKETS + slotsToReserve;
        if (excess <= 0) {
            return;
        }
        List<Map.Entry<String, TokenBucket>> entries = new ArrayList<>(buckets.entrySet());
        entries.sort(Comparator.comparingLong(entry -> entry.getValue().lastAccessMillis));
        int removed = 0;
        for (Map.Entry<String, TokenBucket> entry : entries) {
            if (removed >= excess) {
                break;
            }
            if (entry.getKey().equals(protectedKey)) {
                continue;
            }
            buckets.remove(entry.getKey(), entry.getValue());
            removed++;
        }
    }

    private static Set<String> copyNames(Set<String> source) {
        if (source == null || source.isEmpty()) {
            return Set.of();
        }
        LinkedHashSet<String> copy = new LinkedHashSet<>();
        for (String value : source) {
            Objects.requireNonNull(value, "value");
            String trimmed = value.trim();
            if (!trimmed.isEmpty()) {
                copy.add(trimmed);
            }
        }
        return Set.copyOf(copy);
    }

    private static final class TokenBucket {
        private final int capacity;
        private double tokens;
        private long lastRefillMillis;
        private volatile long lastAccessMillis;

        private TokenBucket(int capacity, long nowMillis) {
            this.capacity = capacity;
            this.tokens = capacity;
            this.lastRefillMillis = nowMillis;
            this.lastAccessMillis = nowMillis;
        }
    }
}