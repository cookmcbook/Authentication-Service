package com.tonyqing.authentication.auth.dto;

public record UserResponse (
    Long id,
    String name,
    String email
) {}