package com.github.dimitryivaniuta.gateway.audit.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;

/**
 * Encrypts/decrypts audit payloads at rest using AES-GCM (envelope encryption).
 *
 * <p>Design:
 * <ul>
 *   <li>DB stores {@link AuditEnvelope} as JSONB (no plaintext PII at rest).</li>
 *   <li>Envelope carries {@code kid} (key-id) to support rotation.</li>
 *   <li>AAD binds ciphertext to immutable event fields (id, createdAt, eventType).</li>
 *   <li>Active kid is stored in DB (promotable) - key material stays in config/secret store.</li>
 * </ul>
 */
@Service
public class AuditCryptoService {

    public static final String ALG = "A256GCM";
    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12;

    private static final long ACTIVE_KID_CACHE_MS = 500; // tiny TTL; avoids DB hit per request

    private final AuditCryptoProperties props;
    private final ObjectMapper mapper;
    private final AuditKeyRingStateRepository stateRepo;
    private final SecureRandom random = new SecureRandom();

    private volatile String defaultActiveKid;
    private volatile Map<String, SecretKeySpec> keyring = Map.of();

    private volatile String cachedActiveKid;
    private volatile long cachedAtMs;

    public AuditCryptoService(AuditCryptoProperties props, ObjectMapper mapper, AuditKeyRingStateRepository stateRepo) {
        this.props = props;
        this.mapper = mapper;
        this.stateRepo = stateRepo;
    }

    @PostConstruct
    void init() {
        Map<String, SecretKeySpec> m = new LinkedHashMap<>();
        if (props.keys() != null) {
            for (AuditCryptoProperties.Key k : props.keys()) {
                if (k == null || k.kid() == null || k.key() == null) continue;
                byte[] keyBytes = Base64.getDecoder().decode(k.key());
                validateAesKeyLength(keyBytes.length);
                m.put(k.kid(), new SecretKeySpec(keyBytes, "AES"));
            }
        }
        if (m.isEmpty()) {
            throw new IllegalStateException("No audit crypto keys configured (app.audit.crypto.keys)");
        }
        this.keyring = Collections.unmodifiableMap(m);

        String configuredActive = props.activeKid();
        this.defaultActiveKid = (configuredActive != null && m.containsKey(configuredActive))
                ? configuredActive
                : m.keySet().iterator().next();

        // Create/align DB state (active kid stored in DB, promotable at runtime)
        stateRepo.ensureInitialized(defaultActiveKid);

        invalidateActiveKidCache();
    }

    public String activeKid() {
        long now = System.currentTimeMillis();
        String cached = cachedActiveKid;
        if (cached != null && (now - cachedAtMs) <= ACTIVE_KID_CACHE_MS) {
            return cached;
        }

        String dbKid = stateRepo.get().map(AuditKeyRingStateRepository.State::activeKid).orElse(null);
        String resolved = (dbKid != null && keyring.containsKey(dbKid)) ? dbKid : defaultActiveKid;

        cachedActiveKid = resolved;
        cachedAtMs = now;
        return resolved;
    }

    void invalidateActiveKidCache() {
        cachedActiveKid = null;
        cachedAtMs = 0;
    }

    public Set<String> kids() {
        return keyring.keySet();
    }

    public boolean hasKid(String kid) {
        return keyring.containsKey(kid);
    }

    public String encryptToJson(String plaintext, UUID eventId, Instant createdAt, String eventType) {
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(eventId, "eventId");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(eventType, "eventType");

        String kid = activeKid();
        SecretKeySpec key = keyring.get(kid);
        if (key == null) {
            throw new IllegalStateException("Active KID not present in keyring: " + kid);
        }

        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);

        byte[] aad = aad(eventId, createdAt, eventType);
        byte[] ct = aesGcm(Cipher.ENCRYPT_MODE, key, iv, aad, plaintext.getBytes(StandardCharsets.UTF_8));

        AuditEnvelope env = new AuditEnvelope(1, ALG, kid,
                Base64.getEncoder().encodeToString(iv),
                Base64.getEncoder().encodeToString(ct));

        try {
            return mapper.writeValueAsString(env);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize audit envelope", e);
        }
    }

    /**
     * Encrypts using an explicit kid (used for re-encryption during rotation).
     */
    String encryptToJsonWithKid(String kid, String plaintext, UUID eventId, Instant createdAt, String eventType) {
        Objects.requireNonNull(kid, "kid");
        Objects.requireNonNull(plaintext, "plaintext");
        SecretKeySpec key = keyring.get(kid);
        if (key == null) {
            throw new IllegalStateException("Unknown kid: " + kid);
        }

        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);

        byte[] aad = aad(eventId, createdAt, eventType);
        byte[] ct = aesGcm(Cipher.ENCRYPT_MODE, key, iv, aad, plaintext.getBytes(StandardCharsets.UTF_8));

        AuditEnvelope env = new AuditEnvelope(1, ALG, kid,
                Base64.getEncoder().encodeToString(iv),
                Base64.getEncoder().encodeToString(ct));

        try {
            return mapper.writeValueAsString(env);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize audit envelope", e);
        }
    }

    public String decryptFromJson(String envelopeJson, UUID eventId, Instant createdAt, String eventType) {
        Objects.requireNonNull(envelopeJson, "envelopeJson");
        AuditEnvelope env;
        try {
            env = mapper.readValue(envelopeJson, AuditEnvelope.class);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid audit envelope JSON", e);
        }
        if (env.kid() == null) {
            throw new IllegalStateException("Audit envelope missing kid");
        }
        SecretKeySpec key = keyring.get(env.kid());
        if (key == null) {
            throw new IllegalStateException("No key material configured for kid: " + env.kid());
        }
        if (!ALG.equals(env.alg())) {
            throw new IllegalStateException("Unsupported alg: " + env.alg());
        }

        byte[] iv = Base64.getDecoder().decode(env.iv());
        byte[] ct = Base64.getDecoder().decode(env.ct());
        byte[] aad = aad(eventId, createdAt, eventType);

        byte[] pt = aesGcm(Cipher.DECRYPT_MODE, key, iv, aad, ct);
        return new String(pt, StandardCharsets.UTF_8);
    }

    private static byte[] aesGcm(int mode, SecretKeySpec key, byte[] iv, byte[] aad, byte[] in) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(mode, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            cipher.updateAAD(aad);
            return cipher.doFinal(in);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM operation failed", e);
        }
    }

    private static byte[] aad(UUID eventId, Instant createdAt, String eventType) {
        return (eventId + "|" + createdAt + "|" + eventType).getBytes(StandardCharsets.UTF_8);
    }

    private static void validateAesKeyLength(int len) {
        if (len != 16 && len != 24 && len != 32) {
            throw new IllegalArgumentException("Invalid AES key length: " + len + " (expected 16/24/32 bytes)");
        }
    }
}
