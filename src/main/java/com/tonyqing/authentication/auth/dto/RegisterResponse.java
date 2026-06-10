package com.tonyqing.authentication.auth.dto;

public record RegisterResponse (
    Long id,
    String name,
    String email
) {}