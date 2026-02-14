package com.github.dimitryivaniuta.gateway.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * Sensitive audit event stored outside of logs.
 */
@Entity
@Table(name = "audit_events", schema = "audit")
public class AuditEvent {

    @Id
    private UUID id;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "event_type", nullable = false, length = 100)
    private String eventType;

    @Column(name = "actor", length = 200)
    private String actor;

    @Column(name = "correlation_id", length = 100)
    private String correlationId;

    @Column(name = "payload", nullable = false, columnDefinition = "jsonb")
    private String payload;

    @Column(name = "prev_hash")
    private byte[] prevHash;

    @Column(name = "hash", nullable = false)
    private byte[] hash;

    protected AuditEvent() {}

    public AuditEvent(UUID id, Instant createdAt, String eventType, String actor, String correlationId, String payload, byte[] prevHash, byte[] hash) {
        this.id = id;
        this.createdAt = createdAt;
        this.eventType = eventType;
        this.actor = actor;
        this.correlationId = correlationId;
        this.payload = payload;
        this.prevHash = prevHash;
        this.hash = hash;
    }

    public UUID getId() { return id; }
    public Instant getCreatedAt() { return createdAt; }
    public String getEventType() { return eventType; }
    public String getActor() { return actor; }
    public String getCorrelationId() { return correlationId; }
    public String getPayload() { return payload; }
    public byte[] getPrevHash() { return prevHash; }
    public byte[] getHash() { return hash; }
}
