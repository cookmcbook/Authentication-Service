package com.tonyqing.authentication.auth.security;
import java.io.IOException;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.tonyqing.authentication.auth.entity.User;
import com.tonyqing.authentication.auth.exception.InvalidSessionException;
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
        // Extract Auth header
        String header = request.getHeader("Authorization");

        // Pass filter chain on without authentication if no valid header is present, 
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        // Extract the token
        String token = header.substring(7);

        try {
            // Find user from token and set authentication
            User user = authService.getUserFromToken(token);

            var authentication = new UsernamePasswordAuthenticationToken(
                    user,
                    null,
                    List.of()
            );

            // Set authentication in context
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (InvalidSessionException ignored) {
            SecurityContextHolder.clearContext();
        }

        // Continue filter chain
        filterChain.doFilter(request, response);
    }
}