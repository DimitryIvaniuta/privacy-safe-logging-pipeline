package com.github.dimitryivaniuta.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies audit store writes and reads.
 */
@ActiveProfiles("test")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuditStoreIT extends TestcontainersConfig {

    @Autowired
    TestRestTemplate rest;

    @Autowired
    JdbcTemplate jdbc;

    @Test
    void storesSensitiveEventAndListsIt() {
        String body = "{\n" +
                "  \"email\": \"sensitive.user@example.com\",\n" +
                "  \"phone\": \"+48 600 700 800\",\n" +
                "  \"cardNumber\": \"4111 1111 1111 1111\",\n" +
                "  \"message\": \"store to audit\"\n" +
                "}";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ResponseEntity<String> resp = rest.exchange("/api/demo/sensitive-event", HttpMethod.POST, new HttpEntity<>(body, headers), String.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resp.getBody()).contains("auditEventId");


        // Verify encryption at rest: DB must not contain plaintext PII.
        String uuid = resp.getBody().replaceAll(".*\\\"auditEventId\\\":\\\"([0-9a-fA-F-]+)\\\".*", "$1");
        String rawPayload = jdbc.queryForObject(
                "select payload::text from audit.audit_events where id = ?",
                String.class,
                java.util.UUID.fromString(uuid)
        );
        assertThat(rawPayload).doesNotContain("sensitive.user@example.com");
        assertThat(rawPayload).contains("\"ct\"").contains("\"kid\"");

        HttpHeaders listHeaders = new HttpHeaders();
        listHeaders.setBasicAuth("auditor", "auditor");
        ResponseEntity<String> list = rest.exchange("/api/audit/events?limit=5", HttpMethod.GET, new HttpEntity<>(null, listHeaders), String.class);
        assertThat(list.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(list.getBody()).contains("sensitive.user@example.com");
        assertThat(list.getBody()).contains("\"hash\"");
        assertThat(list.getBody()).contains("\"kid\"");
    }
}
