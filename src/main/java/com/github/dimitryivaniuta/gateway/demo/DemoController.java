package com.github.dimitryivaniuta.gateway.demo;

import com.github.dimitryivaniuta.gateway.audit.AuditService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

/**
 * Demo endpoints to validate redaction + audit sink.
 */
@RestController
@RequestMapping("/api")
public class DemoController {

    private static final Logger log = LoggerFactory.getLogger(DemoController.class);

    private final AuditService auditService;

    public DemoController(AuditService auditService) {
        this.auditService = auditService;
    }

    @PostMapping("/demo/log")
    public ResponseEntity<Map<String, Object>> demoLog(@RequestBody @Valid DemoPayload payload) {
        log.info("demo_payload email={} phone={} card={} message={}",
                payload.email(), payload.phone(), payload.cardNumber(), payload.message());

        if (payload.message().toLowerCase().contains("boom")) {
            throw new IllegalArgumentException("Boom for email=" + payload.email() + " phone=" + payload.phone());
        }

        return ResponseEntity.ok(Map.of("status", "ok"));
    }

    @PostMapping("/demo/sensitive-event")
    public ResponseEntity<Map<String, Object>> sensitiveEvent(@RequestBody @Valid DemoPayload payload) {
        UUID id = auditService.store("DEMO_SENSITIVE_EVENT", "demo-user", payload);
        log.info("audit_event_stored id={} type={}", id, "DEMO_SENSITIVE_EVENT");
        return ResponseEntity.ok(Map.of("auditEventId", id.toString()));
    }

/**
 * Demonstrates that even if someone incorrectly writes PII to MDC, it gets redacted.
 */
@PostMapping("/demo/mdc-leak")
public ResponseEntity<Map<String, Object>> mdcLeak(@RequestBody @Valid DemoPayload payload) {
    MDC.put("userEmail", payload.email());
    try {
        log.info("mdc_leak_test message=hello");
    } finally {
        MDC.remove("userEmail");
    }
    return ResponseEntity.ok(Map.of("status", "ok"));
}

}
