package com.github.dimitryivaniuta.gateway.audit;

import com.github.dimitryivaniuta.gateway.http.CorrelationIdFilter;
import com.github.dimitryivaniuta.gateway.audit.crypto.AuditCryptoService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.MDC;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Stores sensitive events in DB (audit schema). Never logs raw payload.
 */
@Service
public class AuditService {

    private final AuditEventRepository repository;
    private final ObjectMapper mapper;
    private final JdbcTemplate jdbc;
    private final AuditCryptoService crypto;

    public AuditService(AuditEventRepository repository, ObjectMapper mapper, JdbcTemplate jdbc, AuditCryptoService crypto) {
        this.repository = repository;
        this.mapper = mapper;
        this.jdbc = jdbc;
        this.crypto = crypto;
    }

    @Transactional
    public UUID store(String eventType, String actor, Object payload) {
        UUID id = UUID.randomUUID();
        String correlationId = MDC.get(CorrelationIdFilter.MDC_KEY);

        final String json;
        try {
            json = mapper.writeValueAsString(payload);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize audit payload", e);
        }

        jdbc.queryForObject("select pg_advisory_xact_lock(?)", Long.class, 42_4242L);
        AuditEvent latest = repository.findLatest();
        byte[] prevHash = latest == null ? null : latest.getHash();
        Instant createdAt = Instant.now();

        // Hash chain is computed over plaintext (logical integrity).
        byte[] hash = AuditHashChain.compute(prevHash, createdAt, eventType, actor, correlationId, json);

        // Persist encrypted envelope JSON (no plaintext PII at rest).
        String envelopeJson = crypto.encryptToJson(json, id, createdAt, eventType);

        repository.save(new AuditEvent(id, createdAt, eventType, actor, correlationId, envelopeJson, prevHash, hash));
        return id;
    }

    public List<AuditEvent> recent(int limit) {
        int safeLimit = Math.max(1, Math.min(limit, 200));
        return repository.findRecent(PageRequest.of(0, safeLimit));
    }
}
