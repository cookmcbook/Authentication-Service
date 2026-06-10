
package com.tonyqing.authentication.auth.service;

import com.tonyqing.authentication.auth.repository.SessionRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

@Service
public class SessionCleanupService {
    private static final Logger log = LoggerFactory.getLogger(SessionCleanupService.class);
    private final SessionRepository sessionRepository;

    public SessionCleanupService(SessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    // Runs every hour to clean up expired sessions
    @Scheduled(cron = "0 0 * * * *")
    public void cleanExpiredSessions() {
        log.info("Starting scheduled session pruning...");
        sessionRepository.deleteByExpiresAtBefore(Instant.now());
    }
}
