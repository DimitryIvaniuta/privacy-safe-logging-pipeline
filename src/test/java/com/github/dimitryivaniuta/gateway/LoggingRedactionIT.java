package com.github.dimitryivaniuta.gateway;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies correlationId + PII redaction in logs.
 */
@ActiveProfiles("test")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class LoggingRedactionIT extends TestcontainersConfig {

    @Autowired
    TestRestTemplate rest;

    @Test
    void redactsPiiInLogsAndReturnsCorrelationHeader(CapturedOutput output) {
        String email = "john.doe@example.com";
        String phone = "+48 500 600 700";
        String card = "4111 1111 1111 1111";

        String body = "{\n" +
                "  \"email\": \"" + email + "\",\n" +
                "  \"phone\": \"" + phone + "\",\n" +
                "  \"cardNumber\": \"" + card + "\",\n" +
                "  \"message\": \"hello\"\n" +
                "}";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Correlation-Id", "it-corr-1");

        ResponseEntity<String> resp = rest.exchange("/api/demo/log", HttpMethod.POST, new HttpEntity<>(body, headers), String.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resp.getHeaders().getFirst("X-Correlation-Id")).isEqualTo("it-corr-1");

        String logs = output.getOut();
        assertThat(logs).doesNotContain(email);
        assertThat(logs).doesNotContain(phone);
        assertThat(logs).doesNotContain(card);
        assertThat(logs).contains("@example.com");
        assertThat(logs).contains("**** **** **** 1111");
        assertThat(logs).contains("it-corr-1");
    }

    @Test
    void redactsPiiInExceptionLogs(CapturedOutput output) {
        String email = "alice@example.com";
        String phone = "+1 (415) 555-2671";

        String body = "{\n" +
                "  \"email\": \"" + email + "\",\n" +
                "  \"phone\": \"" + phone + "\",\n" +
                "  \"cardNumber\": \"4111 1111 1111 1111\",\n" +
                "  \"message\": \"boom\"\n" +
                "}";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ResponseEntity<String> resp = rest.exchange("/api/demo/log", HttpMethod.POST, new HttpEntity<>(body, headers), String.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        String logs = output.getOut();
        assertThat(logs).doesNotContain(email);
        assertThat(logs).doesNotContain(phone);
    }

@Test
void redactsPiiInMdc(CapturedOutput output) {
    String email = "mdc.user@example.com";

    String body = "{\n" +
            "  \"email\": \"" + email + "\",\n" +
            "  \"phone\": \"+48 501 601 701\",\n" +
            "  \"cardNumber\": \"4111 1111 1111 1111\",\n" +
            "  \"message\": \"hello\"\n" +
            "}";

    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);

    ResponseEntity<String> resp = rest.exchange("/api/demo/mdc-leak", HttpMethod.POST, new HttpEntity<>(body, headers), String.class);
    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);

    String logs = output.getOut();
    assertThat(logs).doesNotContain(email);
    assertThat(logs).contains("@example.com");
}

}
