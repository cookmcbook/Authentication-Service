
package com.tonyqing.authentication.auth.service;

import com.tonyqing.authentication.auth.repository.ResetTokenRepository;
import com.tonyqing.authentication.auth.repository.SessionRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

@Service
public class CleanupService {
    private static final Logger log = LoggerFactory.getLogger(CleanupService.class);
    private final SessionRepository sessionRepository;
    private final ResetTokenRepository resetTokenRepository;


    public CleanupService(SessionRepository sessionRepository, ResetTokenRepository resetTokenRepository) {
        this.sessionRepository = sessionRepository;
        this.resetTokenRepository = resetTokenRepository;
    }

    // Runs every hour to clean up expired sessions
    @Scheduled(cron = "0 0 * * * *")
    public void cleanExpiredSessions() {
        log.info("Starting scheduled session pruning...");
        sessionRepository.deleteByExpiresAtBefore(Instant.now());
        resetTokenRepository.deleteByExpiresAtBefore(Instant.now());
        log.info("Finished scheduled session pruning.");

    }
}
