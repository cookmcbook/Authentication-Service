package com.tonyqing.authentication.auth.service;

import com.tonyqing.authentication.auth.dto.UserRequest;
import com.tonyqing.authentication.auth.entity.User;
import com.tonyqing.authentication.auth.repository.SessionRepository;
import com.tonyqing.authentication.auth.repository.UserRepository;
import com.tonyqing.authentication.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest
class AuthServiceTests {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserRepository userRepository;
    
    @Test
    void register_shouldCreateUserWithHashedPassword() {
        UserRequest request = new UserRequest("Tony", "tony@example.com");
        authService.register(request);

        User user = userRepository.findByEmail("tony@example.com").orElseThrow();

        assertThat(user.getDisplayName()).isEqualTo("Tony");
        assertThat(user.getEmail()).isEqualTo("tony@example.com");
    }

    @Test
    void register_shouldRejectDuplicateEmail() {
        UserRequest request = new UserRequest("Tony", "tony@example.com");
        authService.register(request);

        assertThatThrownBy(() ->
                authService.register(new UserRequest("Other", "tony@example.com"))
        ).isInstanceOf(RuntimeException.class);
    }

    @TestConfiguration
    static class TestConfig {
        @Bean
        AuthService authService(
                UserRepository userRepository,
                SessionRepository sessionRepository
        ) {
            return new AuthService(userRepository, sessionRepository);
        }
    }
}