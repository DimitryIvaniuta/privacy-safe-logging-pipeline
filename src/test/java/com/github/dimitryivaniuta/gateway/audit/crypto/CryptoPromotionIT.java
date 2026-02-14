package com.github.dimitryivaniuta.gateway.audit.crypto;

import com.github.dimitryivaniuta.gateway.TestcontainersConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies DB-backed active kid promotion works.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@ActiveProfiles("test")
class CryptoPromotionIT extends TestcontainersConfig {

    @Autowired
    AuditCryptoService crypto;

    @Autowired
    AuditKeyRingStateRepository state;

    @Test
    void promoteChangesActiveKid() {
        String initial = crypto.activeKid();
        String next = initial.equals("k1") ? "k0" : "k1";

        state.promote(next, "test");
        crypto.invalidateActiveKidCache();

        assertThat(crypto.activeKid()).isEqualTo(next);
    }
}
