package com.tonyqing.authentication.auth.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.tonyqing.authentication.auth.dto.LoginRequest;
import com.tonyqing.authentication.auth.dto.LoginResponse;
import com.tonyqing.authentication.auth.repository.UserRepository;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    

    private final UserRepository userRepository;

    public AuthController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        return userRepository.findByEmail(request.email())
                .map(user -> {
                    String token = UUID.randomUUID().toString();

                    return ResponseEntity.ok(new LoginResponse(token));
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

}
