package cn.tolim.spissatus4j.policy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** Deterministic, manually advanced clock for rate-limit and expiry tests. */
final class MutableClock extends Clock {

    private Instant instant;

    MutableClock(Instant start) {
        this.instant = start;
    }

    void advance(Duration duration) {
        this.instant = this.instant.plus(duration);
    }

    void set(Instant value) {
        this.instant = value;
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return instant;
    }
}