package com.github.dimitryivaniuta.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies audit endpoints are protected in local-basic profile.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("basic")
class AuditSecurityBasicProfileIT extends TestcontainersConfig {

    @Autowired
    TestRestTemplate rest;

    @Test
    void auditEndpointRequiresAuth() {
        ResponseEntity<String> unauth = rest.getForEntity("/api/audit/events?limit=1", String.class);
        assertThat(unauth.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth("auditor", "auditor");
        ResponseEntity<String> auth = rest.exchange("/api/audit/events?limit=1", HttpMethod.GET, new HttpEntity<>(null, headers), String.class);
        assertThat(auth.getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
