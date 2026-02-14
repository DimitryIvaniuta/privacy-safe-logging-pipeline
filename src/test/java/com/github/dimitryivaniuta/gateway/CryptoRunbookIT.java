package com.github.dimitryivaniuta.gateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies safe promote runbook generates key, promotes it, and encrypts new events with new kid.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class CryptoRunbookIT extends TestcontainersConfig {

    @Autowired
    TestRestTemplate rest;

    @Autowired
    ObjectMapper mapper;

    @Test
    void safePromoteRunbookPromotesAndEncryptsWithNewKid() throws Exception {
        ResponseEntity<String> runbook = rest.postForEntity("/api/admin/crypto/runbook/safe-promote?kid=k-runbook&graceDays=1", null, String.class);
        assertThat(runbook.getStatusCode()).isEqualTo(HttpStatus.OK);

        JsonNode rb = mapper.readTree(runbook.getBody());
        assertThat(rb.get("promoted").get("activeKid").asText()).isEqualTo("k-runbook");
        assertThat(rb.get("generated").get("keyBase64").asText()).isNotBlank();

        // Create sensitive event -> should be stored under the new active kid
        String body = "{\n" +
                "  \"email\": \"runbook.user@example.com\",\n" +
                "  \"phone\": \"+48 501 601 701\",\n" +
                "  \"cardNumber\": \"4111 1111 1111 1111\",\n" +
                "  \"message\": \"sensitive\"\n" +
                "}";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<String> resp = rest.exchange("/api/demo/sensitive-event", HttpMethod.POST, new HttpEntity<>(body, headers), String.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<String> health = rest.getForEntity("/api/admin/crypto/health", String.class);
        JsonNode h = mapper.readTree(health.getBody());
        JsonNode counts = h.get("eventCountsByKid");
        assertThat(counts.has("k-runbook")).isTrue();
        assertThat(counts.get("k-runbook").asLong()).isGreaterThan(0);
    }
}
