package com.github.dimitryivaniuta.gateway.audit.crypto;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

/**
 * Stores the runtime "active key id" (kid) in the database so operators can promote keys
 * without redeploying and without changing configuration.
 *
 * <p>Key material itself remains in configuration/secret store. DB stores only the active kid.</p>
 */
@Repository
public class AuditKeyRingStateRepository {

    private final JdbcTemplate jdbc;

    public AuditKeyRingStateRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<State> get() {
        return jdbc.query(
                "select active_kid, promoted_at, promoted_by, version from audit.crypto_keyring_state where id = 1",
                rs -> rs.next()
                        ? Optional.of(new State(
                                rs.getString("active_kid"),
                                rs.getTimestamp("promoted_at").toInstant(),
                                rs.getString("promoted_by"),
                                rs.getInt("version")
                        ))
                        : Optional.empty()
        );
    }

    /**
     * Ensures the singleton row exists and aligns initial value to configured active kid.
     * If an operator already promoted (version &gt; 0), we keep DB value.
     */
    @Transactional
    public State ensureInitialized(String configuredActiveKid) {
        // Insert if missing
        jdbc.update(
                "insert into audit.crypto_keyring_state (id, active_kid) " +
                        "select 1, ? where not exists (select 1 from audit.crypto_keyring_state where id = 1)",
                configuredActiveKid
        );

        State s = get().orElseThrow();

        // Bootstrap alignment: if still at version=0 and promoted_by is null, allow config to set initial value.
        if (s.version() == 0 && s.promotedBy() == null && !s.activeKid().equals(configuredActiveKid)) {
            jdbc.update(
                    "update audit.crypto_keyring_state set active_kid = ?, promoted_at = now(), promoted_by = null where id = 1",
                    configuredActiveKid
            );
            s = get().orElseThrow();
        }
        return s;
    }

    @Transactional
    public State promote(String newActiveKid, String promotedBy) {
        jdbc.update(
                "update audit.crypto_keyring_state " +
                        "set active_kid = ?, promoted_at = now(), promoted_by = ?, version = version + 1 " +
                        "where id = 1",
                newActiveKid,
                promotedBy
        );
        return get().orElseThrow();
    }

    public record State(String activeKid, Instant promotedAt, String promotedBy, int version) {}
}
