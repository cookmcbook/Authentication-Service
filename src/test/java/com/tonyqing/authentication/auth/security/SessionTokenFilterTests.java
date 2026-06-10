package com.tonyqing.authentication.auth.security;

import com.tonyqing.authentication.auth.entity.Session;
import com.tonyqing.authentication.auth.entity.User;
import com.tonyqing.authentication.auth.exception.InvalidSessionException;
import com.tonyqing.authentication.auth.security.SessionTokenFilter;
import com.tonyqing.authentication.auth.service.AuthService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SessionTokenFilterTests {

    @Mock
    private AuthService authService;

    @Mock
    private FilterChain filterChain;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @InjectMocks
    private SessionTokenFilter filter;

    @BeforeEach
    void setUp() {
        // Clear the context before each test to ensure isolation
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldAuthenticateWithValidToken() throws ServletException, IOException {
        // Given
        String token = "valid-session-token";
        User user = new User("Tony", "tony@example.com", "password");

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(authService.getUserFromToken(token)).thenReturn(user);

        // When
        filter.doFilter(request, response, filterChain);

        // Then
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal()).isEqualTo(user);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotAuthenticateWithExpiredToken() throws ServletException, IOException {
        // Given
        String token = "expired-token";

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(authService.getUserFromToken(token)).thenThrow(new InvalidSessionException("Session expired"));

        // When
        filter.doFilter(request, response, filterChain);

        // Then
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldContinueChainWhenNoHeaderIsPresent() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn(null);

        // When
        filter.doFilter(request, response, filterChain);

        // Then
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }
}