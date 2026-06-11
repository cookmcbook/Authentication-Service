package com.tonyqing.authentication.auth.dto;

public record RegisterResponse (
    Long id,
    String displayName,
    String email
) {}