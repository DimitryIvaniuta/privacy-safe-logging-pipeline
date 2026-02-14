package com.github.dimitryivaniuta.gateway.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;

/**
 * Computes tamper-evident hash chain values for audit events.
 *
 * <p>hash = SHA-256(prevHash + createdAt + eventType + actor + correlationId + payload)</p>
 */
public final class AuditHashChain {

    private AuditHashChain() {}

    public static byte[] compute(byte[] prevHash, Instant createdAt, String eventType, String actor, String correlationId, String payload) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            if (prevHash != null) md.update(prevHash);
            md.update(createdAt.toString().getBytes(StandardCharsets.UTF_8));
            md.update(nullSafe(eventType));
            md.update(nullSafe(actor));
            md.update(nullSafe(correlationId));
            md.update(nullSafe(payload));
            return md.digest();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute audit hash", e);
        }
    }

    private static byte[] nullSafe(String s) {
        return (s == null ? "" : s).getBytes(StandardCharsets.UTF_8);
    }

    public static String hex(byte[] bytes) {
        if (bytes == null) return null;
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
