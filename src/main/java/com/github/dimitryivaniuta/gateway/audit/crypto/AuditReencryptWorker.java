package com.github.dimitryivaniuta.gateway.audit.crypto;

import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Background worker that processes re-encryption jobs in small throttled batches.
 */
@Component
@EnableScheduling
@Profile("!test")
public class AuditReencryptWorker {

    private final AuditReencryptJobService jobs;
    private final AuditReencryptionService reencrypt;

    public AuditReencryptWorker(AuditReencryptJobService jobs, AuditReencryptionService reencrypt) {
        this.jobs = jobs;
        this.reencrypt = reencrypt;
    }

    @Scheduled(fixedDelayString = "${app.audit.crypto.reencrypt.poll-delay-ms:1000}")
    public void tick() {
        AuditReencryptJobService.Job job = jobs.claimNextRunningJob();
        if (job == null) {
            return;
        }

        try {
            AuditReencryptionService.BatchResult r = reencrypt.reencryptBatchWithCheckpoint(
                    job.fromKid(),
                    job.toKid(),
                    job.batchSize(),
                    job.lastCreatedAt(),
                    job.lastId()
            );

            if (r.processed() > 0) {
                jobs.updateProgress(job.jobId(), r.processed(), r.lastCreatedAt(), r.lastId());
            }

            if (r.done()) {
                jobs.markDone(job.jobId());
            }

            // Throttle outside of DB locks/transactions (reencrypt method is transactional).
            if (job.throttleMs() > 0 && r.processed() > 0) {
                try {
                    Thread.sleep((long) job.throttleMs() * r.processed());
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }

        } catch (Exception e) {
            jobs.markFailed(job.jobId(), abbreviate(e.toString(), 4000));
        }
    }

    private static String abbreviate(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max);
    }
}
