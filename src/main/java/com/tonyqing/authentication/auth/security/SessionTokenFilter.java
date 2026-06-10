package com.tonyqing.authentication.auth.security;
import java.io.IOException;
import java.time.Instant;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.tonyqing.authentication.auth.entity.User;
import com.tonyqing.authentication.auth.exception.InvalidSessionException;
import com.tonyqing.authentication.auth.repository.SessionRepository;
import com.tonyqing.authentication.auth.service.AuthService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class SessionTokenFilter extends OncePerRequestFilter {

    private final AuthService authService;

    public SessionTokenFilter(AuthService authService) {
        this.authService = authService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(7);

        try {
            User user = authService.getUserFromToken(token);

            var authentication = new UsernamePasswordAuthenticationToken(
                    user,
                    null,
                    List.of()
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (InvalidSessionException ignored) {
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}