package com.github.dimitryivaniuta.gateway.audit.crypto;

/**
 * Envelope stored in DB instead of plaintext audit payload.
 *
 * @param v schema version
 * @param alg algorithm identifier
 * @param kid key id used to encrypt
 * @param iv base64 IV (12 bytes)
 * @param ct base64 ciphertext (includes GCM tag)
 */
public record AuditEnvelope(
        int v,
        String alg,
        String kid,
        String iv,
        String ct
) { }
