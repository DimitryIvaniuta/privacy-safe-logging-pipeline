package com.github.dimitryivaniuta.gateway.audit.crypto;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.*;

/**
 * Stores operational key policy metadata (status + deprecation grace period).
 *
 * <p>Key material is not persisted here; only lifecycle state.</p>
 */
@Repository
public class AuditKeyPolicyRepository {

    private final JdbcTemplate jdbc;

    public AuditKeyPolicyRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Map<String, Policy> list() {
        Map<String, Policy> out = new LinkedHashMap<>();
        jdbc.query("select kid, status, deprecated_at, deprecated_until, deprecated_by, updated_at from audit.crypto_key_policy order by kid",
                rs -> {
                    while (rs.next()) {
                        String kid = rs.getString("kid");
                        out.put(kid, new Policy(
                                kid,
                                rs.getString("status"),
                                toInstant(rs.getTimestamp("deprecated_at")),
                                toInstant(rs.getTimestamp("deprecated_until")),
                                rs.getString("deprecated_by"),
                                toInstant(rs.getTimestamp("updated_at"))
                        ));
                    }
                });
        return out;
    }

    public void ensureActivePresent(String kid) {
        jdbc.update("insert into audit.crypto_key_policy(kid,status) select ?, 'ACTIVE' where not exists (select 1 from audit.crypto_key_policy where kid=?)",
                kid, kid);
    }

    public void markActive(String kid) {
        jdbc.update("insert into audit.crypto_key_policy(kid,status,updated_at) values(?, 'ACTIVE', now()) " +
                        "on conflict (kid) do update set status='ACTIVE', deprecated_at=null, deprecated_until=null, deprecated_by=null, updated_at=now()",
                kid);
    }

    public void deprecate(String kid, Instant until, String actor) {
        jdbc.update("insert into audit.crypto_key_policy(kid,status,deprecated_at,deprecated_until,deprecated_by,updated_at) " +
                        "values(?, 'DEPRECATED', now(), ?, ?, now()) " +
                        "on conflict (kid) do update set status='DEPRECATED', deprecated_at=now(), deprecated_until=?, deprecated_by=?, updated_at=now()",
                kid, until == null ? null : java.sql.Timestamp.from(until), actor,
                until == null ? null : java.sql.Timestamp.from(until), actor);
    }

    private static Instant toInstant(java.sql.Timestamp ts) {
        return ts == null ? null : ts.toInstant();
    }

    public record Policy(String kid, String status, Instant deprecatedAt, Instant deprecatedUntil, String deprecatedBy, Instant updatedAt) {}
}
