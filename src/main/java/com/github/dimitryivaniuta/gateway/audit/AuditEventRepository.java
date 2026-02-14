package com.github.dimitryivaniuta.gateway.audit;

import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.UUID;

/**
 * Repository for audit events.
 */
public interface AuditEventRepository extends JpaRepository<AuditEvent, UUID> {

    @Query("select e from AuditEvent e order by e.createdAt desc")
    List<AuditEvent> findRecent(Pageable pageable);

    @Query("select e from AuditEvent e order by e.createdAt desc")
    default AuditEvent findLatest() {
        var list = findRecent(PageRequest.of(0, 1));
        return list.isEmpty() ? null : list.get(0);
    }
}
