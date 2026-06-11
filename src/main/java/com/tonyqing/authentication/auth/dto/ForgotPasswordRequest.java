package com.tonyqing.authentication.auth.dto;

import jakarta.validation.constraints.Email;

public record ForgotPasswordRequest(@Email String email) {}
