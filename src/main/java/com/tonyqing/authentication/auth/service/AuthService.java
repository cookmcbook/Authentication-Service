package com.tonyqing.authentication.auth.service;

import java.time.Instant;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.tonyqing.authentication.auth.dto.LoginRequest;
import com.tonyqing.authentication.auth.dto.LoginResponse;
import com.tonyqing.authentication.auth.dto.RegisterRequest;
import com.tonyqing.authentication.auth.dto.RegisterResponse;
import com.tonyqing.authentication.auth.entity.Session;
import com.tonyqing.authentication.auth.entity.User;
import com.tonyqing.authentication.auth.exception.DuplicateEmailException;
import com.tonyqing.authentication.auth.exception.InvalidSessionException;
import com.tonyqing.authentication.auth.mapper.UserMapper;
import com.tonyqing.authentication.auth.repository.SessionRepository;
import com.tonyqing.authentication.auth.repository.UserRepository;

import jakarta.transaction.Transactional;

@Service
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;

    public AuthService(PasswordEncoder passwordEncoder, UserRepository userRepository, SessionRepository sessionRepository) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
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
                    if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
                        throw new InvalidSessionException("Invalid credentials");
                    }
                    String token = UUID.randomUUID().toString();
                    sessionRepository.save(new Session(token, user));
                    return new LoginResponse(token);
                }).orElseThrow(() -> new InvalidSessionException(request.email()));
    }
    
    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new DuplicateEmailException(request.email());
        }
        // Hash password
        String hashedPassword = passwordEncoder.encode(request.password());
        
        User user = new User(request.name(), request.email(), hashedPassword);

        return UserMapper.toResponse(userRepository.save(user));
    }

}
