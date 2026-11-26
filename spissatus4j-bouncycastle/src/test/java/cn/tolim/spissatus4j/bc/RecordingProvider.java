package cn.tolim.spissatus4j.bc;

import java.security.Provider;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Wraps a real provider and records every service lookup, so tests can prove
 * that engines are pinned to the configured provider instead of constructing
 * lightweight implementations directly or falling back to another provider.
 */
final class RecordingProvider extends Provider {

    private static final long serialVersionUID = 1L;

    private final Provider delegate;
    private final List<String> requests = Collections.synchronizedList(new ArrayList<>());

    RecordingProvider(Provider delegate) {
        super(delegate.getName() + "-recording", delegate.getVersionStr(),
                "Recording wrapper for tests");
        this.delegate = delegate;
    }

    @Override
    public Service getService(String type, String algorithm) {
        requests.add(type + ":" + algorithm);
        return delegate.getService(type, algorithm);
    }

    /** Returns the recorded {@code type:algorithm} lookups in call order. */
    List<String> requests() {
        synchronized (requests) {
            return List.copyOf(requests);
        }
    }

    boolean requested(String type, String algorithm) {
        return requests.contains(type + ":" + algorithm);
    }
}