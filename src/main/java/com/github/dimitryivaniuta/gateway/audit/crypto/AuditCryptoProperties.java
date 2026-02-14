package com.github.dimitryivaniuta.gateway.audit.crypto;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Encryption configuration for audit payloads (envelope encryption).
 *
 * <p>Keys are configured as Base64-encoded AES keys (16/24/32 bytes => AES-128/192/256).
 * The service uses AES-GCM with a random 12-byte IV.</p>
 */
@ConfigurationProperties(prefix = "app.audit.crypto")
public record AuditCryptoProperties(
        String activeKid,
        List<Key> keys
) {
    public record Key(String kid, String key) {}
}
