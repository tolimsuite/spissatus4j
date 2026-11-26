package cn.tolim.spissatus4j.core.audit;

import cn.tolim.spissatus4j.contract.audit.AuditEvent;
import cn.tolim.spissatus4j.contract.exception.AuditException;
import cn.tolim.spissatus4j.contract.exception.ErrorCode;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Canonical audit encoding and HMAC-SHA256 chain hashing.
 *
 * <p>Every field is length-prefixed or null-marked to make the encoding
 * unambiguous. Detail keys are sorted so map iteration order cannot change a
 * hash. This is an internal core helper; the audit module documents and tests
 * the same canonical rule for its own trail.</p>
 */
public final class AuditHashing {

    private static final String MAGIC = "SPS4AUD1";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private AuditHashing() {
    }

    public static String hash(SecretKey key, long sequence, String previousHash, AuditEvent event) {
        try {
            byte[] canonical = canonicalBytes(sequence, previousHash, event);
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key.getEncoded(), HMAC_ALGORITHM));
            return HexFormat.of().formatHex(mac.doFinal(canonical));
        } catch (Exception e) {
            throw new AuditException(ErrorCode.AUDIT_FAILURE, "Audit chain hashing failed", e);
        }
    }

    public static byte[] canonicalBytes(long sequence, String previousHash, AuditEvent event) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream(512);
            try (DataOutputStream out = new DataOutputStream(buffer)) {
                writeString(out, MAGIC);
                out.writeLong(sequence);
                writeString(out, previousHash);
                writeString(out, event.eventId().toString());
                out.writeLong(event.timestamp().toEpochMilli());
                writeString(out, event.type().name());
                writeString(out, event.severity().name());
                writeString(out, event.outcome().name());
                writeString(out, event.callerId());
                writeString(out, event.tenantId());
                writeString(out, event.algorithm() == null ? null : event.algorithm().id());
                writeString(out, event.keyId() == null ? null : event.keyId().value());
                out.writeBoolean(event.keyVersion() != null);
                if (event.keyVersion() != null) {
                    out.writeLong(event.keyVersion().value());
                }
                writeString(out, event.operation() == null ? null : event.operation().name());
                writeString(out, event.message());
                List<Map.Entry<String, String>> entries = new ArrayList<>(event.details().entrySet());
                entries.sort(Map.Entry.comparingByKey());
                out.writeInt(entries.size());
                for (Map.Entry<String, String> entry : entries) {
                    writeString(out, entry.getKey());
                    writeString(out, entry.getValue());
                }
            }
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new AuditException(ErrorCode.AUDIT_FAILURE, "Audit canonicalization failed", e);
        }
    }

    private static void writeString(DataOutputStream out, String value) throws IOException {
        out.writeBoolean(value != null);
        if (value != null) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            out.writeInt(bytes.length);
            out.write(bytes);
        }
    }
}