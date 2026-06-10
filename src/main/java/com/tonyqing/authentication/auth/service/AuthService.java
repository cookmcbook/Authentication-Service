package com.tonyqing.authentication.auth.service;

import java.time.Instant;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.tonyqing.authentication.auth.dto.LoginRequest;
import com.tonyqing.authentication.auth.dto.LoginResponse;
import com.tonyqing.authentication.auth.entity.Session;
import com.tonyqing.authentication.auth.entity.User;
import com.tonyqing.authentication.auth.exception.InvalidSessionException;
import com.tonyqing.authentication.auth.exception.UserNotFoundException;
import com.tonyqing.authentication.auth.repository.SessionRepository;
import com.tonyqing.authentication.auth.repository.UserRepository;

import jakarta.transaction.Transactional;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;

    public AuthService(UserRepository userRepository, SessionRepository sessionRepository) {
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
    }

    public boolean isAuthenticated(String token) {
        return sessionRepository.findByToken(token)
                .map(session -> {
                    // Check if the session is still valid
                    if (session.getExpiresAt().isAfter(Instant.now())) {
                        return true;
                    } else {
                        // Delete the expired session
                        sessionRepository.delete(session);
                        return false;
                    }
                })
                .orElse(false);
    }

    public User getUserFromToken(String token) {
        Session session = sessionRepository.findByToken(token)
                .orElseThrow(() -> new InvalidSessionException("Invalid session token"));

        if (session.getExpiresAt().isBefore(Instant.now())) {
            sessionRepository.delete(session);
            throw new InvalidSessionException("Session token expired");
        }

        return session.getUser();
    }

    @Transactional
    public LoginResponse login(LoginRequest request) {
        return userRepository.findByEmail(request.email())
                .map(user -> {
                    String token = UUID.randomUUID().toString();
                    sessionRepository.save(new Session(token, user));
                    return new LoginResponse(token);
                }).orElseThrow(() -> new UserNotFoundException(request.email()));
    }     
}
