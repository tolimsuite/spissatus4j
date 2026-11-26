package cn.tolim.spissatus4j.envelope;

import cn.tolim.spissatus4j.contract.exception.ConfigurationException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import cn.tolim.spissatus4j.contract.spi.ModuleContext;
import cn.tolim.spissatus4j.contract.spi.SpissatusModule;
import cn.tolim.spissatus4j.envelope.codec.JsonEnvelopeCodec;
import cn.tolim.spissatus4j.envelope.codec.TlvEnvelopeCodec;
import cn.tolim.spissatus4j.envelope.internal.DefaultEnvelopeService;
import cn.tolim.spissatus4j.envelope.internal.DefaultVersionPolicy;
import cn.tolim.spissatus4j.envelope.internal.EnvelopeLimits;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.WeakHashMap;

/**
 * ServiceLoader module contributing the envelope service and both structural
 * codecs.
 *
 * <p>Supported setting: {@code spissatus.envelope.max-bytes} (default
 * 268435456) caps the size of encoded and decoded envelopes.</p>
 */
public final class EnvelopeModule implements SpissatusModule {

    public static final String MODULE_ID = "envelope";
    public static final int ORDER = 300;
    public static final String MAX_BYTES_SETTING = "spissatus.envelope.max-bytes";

    private final Map<ModuleContext, Boolean> contributed =
            Collections.synchronizedMap(new WeakHashMap<>());

    @Override
    public String moduleId() {
        return MODULE_ID;
    }

    @Override
    public int order() {
        return ORDER;
    }

    @Override
    public void contribute(ModuleContext context) {
        Objects.requireNonNull(context, "context");
        synchronized (contributed) {
            if (contributed.containsKey(context)) {
                return;
            }
            int maxBytes = resolveMaxBytes(context);
            TlvEnvelopeCodec tlvCodec = new TlvEnvelopeCodec(maxBytes);
            JsonEnvelopeCodec jsonCodec = new JsonEnvelopeCodec(maxBytes);
            DefaultEnvelopeService service = new DefaultEnvelopeService(
                    List.of(tlvCodec, jsonCodec), new DefaultVersionPolicy(), maxBytes);
            context.registerEnvelopeCodec(tlvCodec);
            context.registerEnvelopeCodec(jsonCodec);
            context.registerEnvelopeService(service);
            contributed.put(context, Boolean.TRUE);
        }
    }

    private static int resolveMaxBytes(ModuleContext context) {
        Optional<String> configured = context.setting(MAX_BYTES_SETTING);
        if (configured.isEmpty()) {
            return EnvelopeLimits.DEFAULT_MAX_BYTES;
        }
        String raw = configured.get().trim();
        try {
            long value = Long.parseLong(raw);
            if (value < 1 || value > Integer.MAX_VALUE) {
                throw new NumberFormatException("out of range");
            }
            return (int) value;
        } catch (NumberFormatException e) {
            throw new ConfigurationException(ErrorCode.CONFIGURATION_INVALID,
                    "Invalid " + MAX_BYTES_SETTING + " setting");
        }
    }

    @Override
    public String toString() {
        return "EnvelopeModule[order=" + ORDER + "]";
    }
}