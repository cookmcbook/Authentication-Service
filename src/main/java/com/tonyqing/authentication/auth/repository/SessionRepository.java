package com.tonyqing.authentication.auth.repository;

import com.tonyqing.authentication.auth.entity.Session;
import com.tonyqing.authentication.auth.entity.User;

import java.time.Instant;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface SessionRepository extends JpaRepository<Session, Long>{
    public Optional<Session> findByToken(String token);

    @Transactional
    void deleteByUser(User user);

    @Transactional
    void deleteByExpiresAtBefore(Instant now);

    @Transactional
    void deleteByToken(String token);
}
