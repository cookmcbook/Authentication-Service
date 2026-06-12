package com.tonyqing.authentication.auth.service;

import com.tonyqing.authentication.auth.dto.LoginRequest;
import com.tonyqing.authentication.auth.dto.RegisterRequest;
import com.tonyqing.authentication.auth.dto.RegisterResponse;
import com.tonyqing.authentication.auth.dto.ResetPasswordRequest;
import com.tonyqing.authentication.auth.dto.ForgotPasswordRequest;

import com.tonyqing.authentication.auth.dto.TokenResponse;
import com.tonyqing.authentication.auth.entity.Session;
import com.tonyqing.authentication.auth.entity.User;
import com.tonyqing.authentication.auth.exception.InvalidSessionException;
import com.tonyqing.authentication.auth.repository.ResetTokenRepository;
import com.tonyqing.authentication.auth.repository.SessionRepository;
import com.tonyqing.authentication.auth.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;

@DataJpaTest
class AuthServiceTests {

    @Autowired
    private AuthService authService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private SessionRepository sessionRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void register_shouldCreateUserWithHashedPassword() {
        RegisterRequest request = new RegisterRequest("Tony", "tony@example.com", "password");
        authService.register(request);

        User user = userRepository.findByEmail("tony@example.com").orElseThrow();

        assertThat(user.getDisplayName()).isEqualTo("Tony");
        assertThat(user.getEmail()).isEqualTo("tony@example.com");
        assertThat(user.getPasswordHash()).isNotEqualTo("password");
        assertThat(passwordEncoder.matches(request.password(), user.getPasswordHash()));
    }

    @Test
    void register_shouldRejectDuplicateEmail() {
        RegisterRequest request = new RegisterRequest("Tony", "tony@example.com", "password");
        authService.register(request);

        assertThatThrownBy(() -> authService.register(new RegisterRequest("Other", "tony@example.com", "password")))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void login_shouldRejectInvalidCredentials() {
        authService.register(new RegisterRequest("Tony", "tony@example.com", "password"));
        assertThatThrownBy(() -> authService.login(new LoginRequest("tony@example.com", "wrong")))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void login_shouldCreateSession() {
        RegisterRequest request = new RegisterRequest("Tony", "tony@example.com", "password");
        authService.register(request);
        TokenResponse tokens = authService.login(new LoginRequest("tony@example.com", "password"));
        assertThat(tokens.accessToken()).isNotBlank();
        assertThat(tokens.refreshToken()).isNotBlank();
        assertThat(sessionRepository.findByRefreshToken(authService.hashToken(tokens.refreshToken()))).isPresent();
    }

    @Test
    void login_shouldRejectInvalidEmail() {
        assertThatThrownBy(() -> authService.login(new LoginRequest("missing@example.com", "password")))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void logout_shouldDeleteSession() {
        RegisterRequest request = new RegisterRequest("Tony", "tony@example.com", "password");
        authService.register(request);

        TokenResponse tokens = authService.login(new LoginRequest("tony@example.com", "password"));

        assertThat(sessionRepository.findByRefreshToken(authService.hashToken(tokens.refreshToken())))
                .isPresent();

        authService.logout(tokens.refreshToken());

        assertThat(sessionRepository.findByRefreshToken(authService.hashToken(tokens.refreshToken())))
                .isEmpty();
    }

    @Test
    void refresh_shouldRejectInvalidToken() {
        assertThatThrownBy(() -> authService.refresh("fake-token")).isInstanceOf(InvalidSessionException.class);
    }

    @Test
    void refresh_shouldRejectExpiredToken() {
        RegisterRequest request = new RegisterRequest("Tony", "tony@example.com", "password");
        RegisterResponse response = authService.register(request);
        User user = userRepository.findById(response.id()).orElseThrow();

        Session session = new Session(authService.hashToken("expired-token"), user);
        session.setExpiresAt(Instant.now().minusSeconds(60));

        sessionRepository.save(session);

        assertThatThrownBy(() -> authService.refresh("expired-token")).isInstanceOf(InvalidSessionException.class);
    }

    @Test
    void refresh_shouldGenerateNewAccessToken() {
        RegisterRequest request = new RegisterRequest("Tony", "tony@example.com", "password");
        authService.register(request);

        TokenResponse loginResponse = authService.login(new LoginRequest("tony@example.com", "password"));
        TokenResponse refreshResponse = authService.refresh(loginResponse.refreshToken());
        assertThat(refreshResponse.accessToken()).isNotEqualTo(loginResponse.accessToken());

    }

    @Test
    void forgotPassword_shouldGenerateToken() {
        RegisterRequest registerRequest = new RegisterRequest("Tony", "tony@example.com", "password");
        authService.register(registerRequest);

        var response = authService.forgotPassword(new ForgotPasswordRequest("tony@example.com"));

        assertThat(response.resetToken()).isNotBlank();
    }

    @Test
    void resetPassword_shouldRejectInvalidToken() {
        var request = new com.tonyqing.authentication.auth.dto.ResetPasswordRequest("invalid-token", "newpassword");
        assertThatThrownBy(() -> authService.resetPassword(request))
                .isInstanceOf(InvalidSessionException.class);
    }

    @Test
    void resetPassword_shouldUpdatePassword() {
        authService.register(
                new RegisterRequest("Tony", "tony@example.com", "password"));

        var forgotResponse = authService.forgotPassword(
                new ForgotPasswordRequest("tony@example.com"));

        authService.resetPassword(
                new ResetPasswordRequest(
                        forgotResponse.resetToken(),
                        "new-secure-password"));

        assertThatThrownBy(() -> authService.login(new LoginRequest("tony@example.com", "password")))
                .isInstanceOf(InvalidSessionException.class);

        assertThat(authService.login(
                new LoginRequest("tony@example.com", "new-secure-password")).accessToken()).isNotBlank();
    }

    @TestConfiguration
    static class TestConfig {
        @Bean
        PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }
        
        @Bean
        JwtService jwtService() {
            return new JwtService("a-very-long-and-secure-random-secret-key-that-is-at-least-32-characters");
        }

        @Bean
        AuthService authService(
                PasswordEncoder passwordEncoder,
                UserRepository userRepository,
                SessionRepository sessionRepository,
                ResetTokenRepository resetTokenRepository,
                JwtService jwtService
            ) {
            return new AuthService(passwordEncoder, userRepository, sessionRepository, resetTokenRepository, jwtService);
        }
    }
}