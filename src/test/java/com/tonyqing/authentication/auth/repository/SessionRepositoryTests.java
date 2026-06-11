package com.tonyqing.authentication.auth.repository;

import com.tonyqing.authentication.auth.entity.User;
import com.tonyqing.authentication.auth.entity.Session;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
 import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class SessionRepositoryTests {

    @Autowired
    private SessionRepository sessionRepository;

    @Autowired
    private UserRepository userRepository;

    @Test
    void shouldDeleteExpiredSessions() {
        // Given
        User user = userRepository.save(new User("Tester", "test@example.com", "password"));
        Instant now = Instant.now();
        
        Session valid = new Session("valid-token", user);
        Session expired = new Session("expired-token", user);
        valid.setExpiresAt(now.plus(1, ChronoUnit.HOURS));
        expired.setExpiresAt(now.minus(1, ChronoUnit.HOURS));
        sessionRepository.save(valid);
        sessionRepository.save(expired);

        // When
        sessionRepository.deleteByExpiresAtBefore(now);

        // Then
        Optional<Session> foundValid = sessionRepository.findByRefreshToken(valid.getRefreshToken());
        Optional<Session> foundExpired = sessionRepository.findByRefreshToken(expired.getRefreshToken());
        assertThat(foundValid).isPresent();
        assertThat(foundExpired).isEmpty(); 
    }

}
