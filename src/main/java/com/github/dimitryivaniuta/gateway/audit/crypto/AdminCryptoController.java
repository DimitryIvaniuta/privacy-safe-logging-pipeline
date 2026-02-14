package com.github.dimitryivaniuta.gateway.audit.crypto;

import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;

/**
 * Operational endpoints for audit crypto.
 *
 * <p>Protected by {@code ROLE_ADMIN} (see security config).</p>
 */
@RestController
@RequestMapping("/api/admin/crypto")
public class AdminCryptoController {

    private final AuditCryptoService crypto;
    private final AuditReencryptionService reencrypt;
    private final AuditKeyRingStateRepository state;
    private final AuditReencryptJobService jobs;
    private final JdbcTemplate jdbc;
    private final AuditKeyPolicyRepository policy;

    public AdminCryptoController(AuditCryptoService crypto,
                                 AuditReencryptionService reencrypt,
                                 AuditKeyRingStateRepository state,
                                 AuditReencryptJobService jobs,
                                 JdbcTemplate jdbc,
                                 AuditKeyPolicyRepository policy) {
        this.crypto = crypto;
        this.reencrypt = reencrypt;
        this.state = state;
        this.jobs = jobs;
        this.jdbc = jdbc;
        this.policy = policy;
    }

    @GetMapping("/keys")
    public Map<String, Object> keys() {
        var s = state.get().orElse(null);
        return Map.of(
                "activeKid", crypto.activeKid(),
                "activeKidSource", (s != null && Objects.equals(s.activeKid(), crypto.activeKid())) ? "db" : "config",
                "kids", crypto.kids(),
                "state", s,
                "policy", policy.list()
        );
    }

    /**
     * Promotes (activates) a key id for new encryptions.
     * Key material must already exist in configuration/secret store.
     */
    @PostMapping("/promote")
    public Map<String, Object> promote(@RequestParam String kid,
                                      @RequestParam(defaultValue = "30") int graceDays) {
        if (!crypto.hasKid(kid)) {
            throw new IllegalArgumentException("Unknown kid: " + kid);
        }
        String actor = currentActor();
        String previous = crypto.activeKid();
        var updated = state.promote(kid, actor);
        policy.markActive(kid);
        if (previous != null && !previous.equals(kid)) {
            policy.ensureActivePresent(previous);
            policy.deprecate(previous, Instant.now().plusSeconds((long) graceDays * 24 * 3600), actor);
        }
        crypto.invalidateActiveKidCache();
        return Map.of(
                "activeKid", updated.activeKid(),
                "promotedAt", updated.promotedAt(),
                "promotedBy", updated.promotedBy(),
                "version", updated.version()
        );
    }

    /**
     * Ring health overview: keyring config vs what's present in DB and job status.
     */
    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Long> counts = new LinkedHashMap<>();
        jdbc.query(
                "select payload->>'kid' as kid, count(*) as cnt from audit.audit_events group by payload->>'kid' order by kid",
                rs -> {
                    while (rs.next()) {
                        counts.put(rs.getString("kid"), rs.getLong("cnt"));
                    }
                }
        );

        Set<String> configured = crypto.kids();
        Set<String> unknownKidsInDb = new LinkedHashSet<>();
        for (String kid : counts.keySet()) {
            if (!configured.contains(kid)) unknownKidsInDb.add(kid);
        }

        var s = state.get().orElse(null);

Map<String, AuditKeyPolicyRepository.Policy> pol = policy.list();
List<String> deprecatedExpiredKids = new ArrayList<>();
Instant now = Instant.now();
for (AuditKeyPolicyRepository.Policy p : pol.values()) {
    if ("DEPRECATED".equalsIgnoreCase(p.status()) && p.deprecatedUntil() != null && now.isAfter(p.deprecatedUntil())) {
        deprecatedExpiredKids.add(p.kid());
    }
}

        return Map.of(
                "configuredKids", configured,
                "activeKidResolved", crypto.activeKid(),
                "dbState", s,
                "eventCountsByKid", counts,
                "unknownKidsInDb", unknownKidsInDb,
                "policy", pol,
                "deprecatedExpiredKids", deprecatedExpiredKids
        );
    }

    /**
     * Synchronous one-off re-encryption (manual).
     */
    @PostMapping("/reencrypt")
    public Map<String, Object> reencrypt(@RequestParam String fromKid,
                                         @RequestParam String toKid,
                                         @RequestParam(defaultValue = "200") int limit) {
        int processed = reencrypt.reencryptBatch(fromKid, toKid, limit);
        return Map.of("processed", processed);
    }

    /**
     * Starts a background throttled re-encryption job.
     */
    @PostMapping("/reencrypt/start")
    public Map<String, Object> startReencrypt(@RequestParam String fromKid,
                                              @RequestParam String toKid,
                                              @RequestParam(defaultValue = "200") int batchSize,
                                              @RequestParam(defaultValue = "25") int throttleMs) {
        if (!crypto.hasKid(fromKid)) throw new IllegalArgumentException("Unknown fromKid: " + fromKid);
        if (!crypto.hasKid(toKid)) throw new IllegalArgumentException("Unknown toKid: " + toKid);

        UUID jobId = jobs.start(fromKid, toKid, batchSize, throttleMs, currentActor());
        return Map.of("jobId", jobId.toString(), "status", "RUNNING");
    }

    @GetMapping("/reencrypt/{jobId}")
    public ResponseEntity<?> job(@PathVariable UUID jobId) {
        return jobs.get(jobId)
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/reencrypt/{jobId}/cancel")
    public Map<String, Object> cancel(@PathVariable UUID jobId) {
        boolean ok = jobs.cancel(jobId);
        return Map.of("canceled", ok);
    }

    /**
     * Generates a random AES-256 key in Base64 for configuration.
     * The returned value is not persisted anywhere.
     */
    
/**
 * Safe promote runbook: generate -> validate ring -> print config snippet -> promote (and deprecate old key).
 *
 * <p>This endpoint installs the generated key into an in-memory overlay keyring to allow immediate promotion
 * without a restart for local/dev use. The key is NOT persisted and will be lost on restart.</p>
 */
@PostMapping("/runbook/safe-promote")
public Map<String, Object> safePromoteRunbook(@RequestParam String kid,
                                              @RequestParam(defaultValue = "30") int graceDays) {
    String actor = currentActor();

    // 1) generate key material (AES-256)
    byte[] key = new byte[32];
    new java.security.SecureRandom().nextBytes(key);
    String keyBase64 = Base64.getEncoder().encodeToString(key);

    // 2) install temporarily so promotion works immediately (local/dev)
    crypto.addTemporaryKey(kid, keyBase64);

    // 3) validate ring
    Map<String, Object> ring = health();
    @SuppressWarnings("unchecked")
    Set<String> unknownKidsInDb = (Set<String>) ring.getOrDefault("unknownKidsInDb", Set.of());
    boolean validationOk = unknownKidsInDb.isEmpty();

    // 4) config snippet for secret store
    String snippet = (
            "# Add to your secret store / config (DO NOT commit)\n" +
            "app:\n" +
            "  audit:\n" +
            "    crypto:\n" +
            "      keys:\n" +
            "        - kid: " + kid + "\n" +
            "          key: " + keyBase64 + "\n" +
            "      active-kid: " + kid + "\n"
    );

    // 5) promote and deprecate previous with grace
    Map<String, Object> promoted = promote(kid, graceDays);

    return Map.of(
            "generated", Map.of("kid", kid, "keyBase64", keyBase64),
            "validationOk", validationOk,
            "ringHealth", ring,
            "configSnippet", snippet,
            "promoted", promoted,
            "note", "Key installed only in-memory for immediate use. Persist it in secrets and restart for durability."
    );
}

/**
 * Deprecates a key-id. New encryptions should not use it. Decryption still requires key material configured.
 */
@PostMapping("/deprecate")
public Map<String, Object> deprecate(@RequestParam String kid,
                                     @RequestParam(defaultValue = "30") int graceDays) {
    String actor = currentActor();
    policy.ensureActivePresent(kid);
    Instant until = Instant.now().plusSeconds((long) graceDays * 24 * 3600);
    policy.deprecate(kid, until, actor);
    return Map.of("kid", kid, "status", "DEPRECATED", "deprecatedUntil", until);
}

@GetMapping("/policy")
public Map<String, Object> policy() {
    return Map.of("policy", policy.list());
}

@PostMapping("/generate")
    public Map<String, Object> generate(@RequestParam(defaultValue = "k-new") String kid) {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        return Map.of(
                "kid", kid,
                "keyBase64", Base64.getEncoder().encodeToString(key),
                "hint", "Add this key to app.audit.crypto.keys, then call /api/admin/crypto/promote?kid=" + kid
        );
    }

    private static String currentActor() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a == null || a.getName() == null) {
            return "unknown";
        }
        return a.getName();
    }
}
