package com.tonyqing.authentication.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.tonyqing.authentication.auth.dto.ForgotPasswordRequest;
import com.tonyqing.authentication.auth.dto.ForgotPasswordResponse;
import com.tonyqing.authentication.auth.dto.LoginRequest;
import com.tonyqing.authentication.auth.dto.TokenResponse;
import com.tonyqing.authentication.auth.dto.RegisterRequest;
import com.tonyqing.authentication.auth.dto.RegisterResponse;
import com.tonyqing.authentication.auth.dto.ResetPasswordRequest;
import com.tonyqing.authentication.auth.dto.ResetPasswordResponse;
import com.tonyqing.authentication.auth.entity.ResetToken;
import com.tonyqing.authentication.auth.entity.Session;
import com.tonyqing.authentication.auth.entity.User;
import com.tonyqing.authentication.auth.exception.DuplicateEmailException;
import com.tonyqing.authentication.auth.exception.InvalidSessionException;
import com.tonyqing.authentication.auth.mapper.UserMapper;
import com.tonyqing.authentication.auth.repository.ResetTokenRepository;
import com.tonyqing.authentication.auth.repository.SessionRepository;
import com.tonyqing.authentication.auth.repository.UserRepository;

import jakarta.transaction.Transactional;

@Service
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;
    private final ResetTokenRepository resetTokenRepository;
    private final JwtService jwtService;

    public AuthService(PasswordEncoder passwordEncoder, UserRepository userRepository,
            SessionRepository sessionRepository, ResetTokenRepository resetTokenRepository, JwtService jwtService) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.resetTokenRepository = resetTokenRepository;
        this.jwtService = jwtService;
    }

    public User getUserFromId(Long id) {
        if (id == null) {
            throw new InvalidSessionException("Invalid user id");
        }
        return userRepository.findById(id)
                .orElseThrow(() -> new InvalidSessionException("Invalid user id"));
    }

    public User getUserFromToken(String token) {
        String tokenHash = hashToken(token);
        Session session = sessionRepository.findByRefreshToken(tokenHash)
                .orElseThrow(() -> new InvalidSessionException("Invalid session token"));

        if (session.getExpiresAt().isBefore(Instant.now())) {
            sessionRepository.delete(session);
            throw new InvalidSessionException("Session token expired");
        }

        return session.getUser();
    }

    @Transactional
    public TokenResponse login(LoginRequest request) {
        return userRepository.findByEmail(request.email())
                .map(user -> {
                    if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
                        throw new InvalidSessionException("Invalid credentials");
                    }
                    String accessToken = jwtService.createToken(user);
                    String rawRefreshToken = UUID.randomUUID().toString();
                    String hashedRefreshToken = hashToken(rawRefreshToken);
                    sessionRepository.save(new Session(hashedRefreshToken, user));
                    return new TokenResponse(accessToken, rawRefreshToken);
                }).orElseThrow(() -> new InvalidSessionException(request.email()));
    }

    // Refresh token
    @Transactional
    public TokenResponse refresh(String refreshToken) {
        // validate token
        if (refreshToken == null) {
            throw new InvalidSessionException("Invalid session token");
        }
        String tokenHash = hashToken(refreshToken);
        Session session = sessionRepository.findByRefreshToken(tokenHash)
                .orElseThrow(() -> new InvalidSessionException("Invalid session token"));
        // check if xpired
        if (session.getExpiresAt().isBefore(Instant.now())) {
            throw new InvalidSessionException("Session token expired");
        }

        // Implement Refresh Token Rotation
        sessionRepository.delete(session);
        
        String accessToken = jwtService.createToken(session.getUser());
        String newRawRefreshToken = UUID.randomUUID().toString();
        String newHashedRefreshToken = hashToken(newRawRefreshToken);
        
        sessionRepository.save(new Session(newHashedRefreshToken, session.getUser()));
        return new TokenResponse(accessToken, newRawRefreshToken);
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

    // this doesn't look right to me
    @Transactional
    public void logout(String refreshToken) {
        String tokenHash = hashToken(refreshToken);
        sessionRepository.deleteByRefreshToken(tokenHash);
    }

    @Transactional
    public ForgotPasswordResponse forgotPassword(ForgotPasswordRequest request) {
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new InvalidSessionException("Invalid email"));
        String token = UUID.randomUUID().toString();
        Instant expiresAt = Instant.now().plus(Duration.ofHours(1));

        // Invalidate previous tokens
        resetTokenRepository.deleteByUser(user);
        String tokenHash = hashToken(token);
        ResetToken resetToken = new ResetToken(user, tokenHash, expiresAt);

        resetTokenRepository.save(resetToken);
        // Note: In a real application, you would trigger an email service here to send
        // the token
        return new ForgotPasswordResponse(token);

    }

    @Transactional
    public ResetPasswordResponse resetPassword(ResetPasswordRequest request) {
        String tokenHash = hashToken(request.token());
        ResetToken resetToken = resetTokenRepository.findByTokenHash(tokenHash);
        if (resetToken == null || resetToken.isExpired() || resetToken.isUsed()) {
            throw new InvalidSessionException("Invalid token");
        }
        // update password
        User user = resetToken.getUser();
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        resetToken.setUsedAt(Instant.now());
        resetTokenRepository.save(resetToken);
        return new ResetPasswordResponse(user.getEmail(), user.getDisplayName());
    }

    public static String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
