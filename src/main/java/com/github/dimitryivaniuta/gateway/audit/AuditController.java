package com.github.dimitryivaniuta.gateway.audit;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.github.dimitryivaniuta.gateway.audit.crypto.AuditCryptoService;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Demo read endpoint for audit events (secure in real deployments).
 */
@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditService auditService;
    private final AuditCryptoService crypto;

    public AuditController(AuditService auditService, AuditCryptoService crypto) {
        this.auditService = auditService;
        this.crypto = crypto;
    }

    @GetMapping("/events")
    public ResponseEntity<List<Map<String, Object>>> recent(@RequestParam(defaultValue = "20") int limit) {
        List<AuditEvent> events = auditService.recent(limit);
        var body = events.stream()
                .map(e -> Map.<String, Object>of(
                        "id", e.getId().toString(),
                        "createdAt", e.getCreatedAt().toString(),
                        "eventType", e.getEventType(),
                        "actor", e.getActor(),
                        "correlationId", e.getCorrelationId(),
                        "payload", crypto.decryptFromJson(e.getPayload(), e.getId(), e.getCreatedAt(), e.getEventType()),
                        "kid", crypto.envelopeKid(e.getPayload()),
                        "prevHash", AuditHashChain.hex(e.getPrevHash()),
                        "hash", AuditHashChain.hex(e.getHash())
                ))
                .collect(Collectors.toList());
        return ResponseEntity.ok(body);
    }
}
