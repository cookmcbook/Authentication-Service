package com.tonyqing.authentication.auth.repository;

import java.time.Instant;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tonyqing.authentication.auth.entity.ResetToken;
import com.tonyqing.authentication.auth.entity.User;

public interface ResetTokenRepository extends JpaRepository<ResetToken, Long> {
    ResetToken findByTokenHash(String tokenHash);
    void deleteByUser(User user);
    List<ResetToken> findByUserAndUsedAtIsNull(User user);
    List<ResetToken> findByUsedAtIsNullAndExpiresAtAfter(Instant now);
    void deleteByExpiresAtBefore(Instant now);

}
