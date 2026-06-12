package com.tonyqing.authentication.auth.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.tonyqing.authentication.auth.dto.ForgotPasswordRequest;
import com.tonyqing.authentication.auth.dto.ForgotPasswordResponse;
import com.tonyqing.authentication.auth.dto.LoginRequest;
import com.tonyqing.authentication.auth.dto.LoginResponse;
import com.tonyqing.authentication.auth.dto.TokenResponse;
import com.tonyqing.authentication.auth.dto.RegisterRequest;
import com.tonyqing.authentication.auth.dto.RegisterResponse;
import com.tonyqing.authentication.auth.dto.ResetPasswordRequest;
import com.tonyqing.authentication.auth.dto.ResetPasswordResponse;
import com.tonyqing.authentication.auth.entity.User;
import com.tonyqing.authentication.auth.mapper.UserMapper;
import com.tonyqing.authentication.auth.service.AuthService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/me") 
    public ResponseEntity<RegisterResponse> me(Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        return ResponseEntity.ok(UserMapper.toResponse(user));
    }

    @PostMapping("/login")
    @Transactional
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        TokenResponse response = authService.login(request);
        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", response.refreshToken())
            .httpOnly(true)
            .secure(true) // true in production with HTTPS
            .sameSite("Strict")
            .path("/api/auth/refresh")
            .maxAge(Duration.ofDays(30))
            .build();

        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, refreshCookie.toString()).body(new LoginResponse(response.accessToken()));
    }

    // the status is expected to be 201 Created
    @PostMapping("/register")
    @Transactional
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(201).body(authService.register(request));
    }

    @PostMapping("/refresh")
    @Transactional
    public ResponseEntity<LoginResponse> refresh(@CookieValue (name = "refreshToken") String refreshToken) {
        TokenResponse response = authService.refresh(refreshToken);
        
        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", response.refreshToken())
            .httpOnly(true)
            .secure(true) 
            .sameSite("Strict")
            .path("/api/auth/refresh")
            .maxAge(Duration.ofDays(30))
            .build();

        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, refreshCookie.toString()).body(new LoginResponse(response.accessToken()));
    }

    @PostMapping("/logout")
    @Transactional
    public ResponseEntity<Void> logout(@CookieValue(name = "refreshToken") String refreshToken) {
        authService.logout(refreshToken);
        ResponseCookie deleteCookie = ResponseCookie
        .from("refreshToken", "")
        .httpOnly(true)
        .secure(false)
        .sameSite("Strict")
        .path("/api/auth/refresh")
        .maxAge(0)
        .build();

        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, deleteCookie.toString()).build();
    }

    @PostMapping("/forgot-password")
    @Transactional
    public ResponseEntity<ForgotPasswordResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        ForgotPasswordResponse response = authService.forgotPassword(request);
        return ResponseEntity.ok().body(response);
    }

    @PostMapping("/reset-password")
    @Transactional
    public ResponseEntity<ResetPasswordResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        ResetPasswordResponse response = authService.resetPassword(request);
        return ResponseEntity.ok().body(response);
    }



}
