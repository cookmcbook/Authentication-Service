package com.tonyqing.authentication.auth.repository;

import com.tonyqing.authentication.auth.entity.Session;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionRepository extends JpaRepository<Session, Long>{
    public Optional<Session> findByToken(String token);
}
