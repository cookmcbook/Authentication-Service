package com.tonyqing.authentication.auth.service;

import com.tonyqing.authentication.auth.dto.RegisterRequest;
import com.tonyqing.authentication.auth.entity.User;
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

@DataJpaTest
class AuthServiceTests {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserRepository userRepository;

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

        assertThatThrownBy(() ->
                authService.register(new RegisterRequest("Other", "tony@example.com", "password"))
        ).isInstanceOf(RuntimeException.class);
    }

    @TestConfiguration
    static class TestConfig {
        @Bean
        PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

        @Bean
        AuthService authService(
                PasswordEncoder passwordEncoder,
                UserRepository userRepository,
                SessionRepository sessionRepository
        ) {
            return new AuthService(passwordEncoder, userRepository, sessionRepository);
        }
    }
}