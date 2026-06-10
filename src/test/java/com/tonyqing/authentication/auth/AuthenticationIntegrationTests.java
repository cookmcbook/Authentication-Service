package com.tonyqing.authentication.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tonyqing.authentication.auth.dto.LoginRequest;
import com.tonyqing.authentication.auth.dto.LoginResponse;
import com.tonyqing.authentication.auth.dto.RegisterRequest;
import com.tonyqing.authentication.auth.entity.User;
import com.tonyqing.authentication.auth.repository.UserRepository;
import com.tonyqing.authentication.auth.repository.SessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest
@ActiveProfiles("dev")
@AutoConfigureMockMvc
class AuthenticationIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SessionRepository sessionRepository;

    @BeforeEach
    void cleanUp() {
        sessionRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void shouldRegisterLoginAndAccessProtectedRoute() throws Exception {
        // 1. Register a new account
        RegisterRequest signUpRequest = new RegisterRequest("Tony Qing", "tony@example.com", "password");

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isCreated());

        assertThat(userRepository.findByEmail("tony@example.com")).isPresent();

        // 2. Login to get a token
        // login logic creates a session and returns a token
        LoginRequest loginRequest = new LoginRequest("tony@example.com", "password");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String responseBody = loginResult.getResponse().getContentAsString();
        LoginResponse loginResponse = objectMapper.readValue(responseBody, LoginResponse.class);
        String token = loginResponse.token();

        assertThat(token).isNotBlank();
        assertThat(sessionRepository.findByToken(token)).isPresent();

        // 3. Use the token to make an authenticated request
        // This tests that SessionTokenFilter correctly identifies the user from the DB
        mockMvc.perform(get("/api/auth/me")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("tony@example.com"))
                .andExpect(jsonPath("$.name").value("Tony Qing"));

    }

    @Test
    void shouldRejectMissingTokenOnProtectedRoute() throws Exception {
        RegisterRequest signUpRequest = new RegisterRequest("Tony Qing", "tony@example.com", "password");

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectInvalidTokenOnProtectedRoute() throws Exception {
        RegisterRequest signUpRequest = new RegisterRequest("Tony Qing", "tony@example.com", "password");

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isCreated());


        mockMvc.perform(get("/api/auth/me")
                .header("Authorization", "Bearer fake-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectDuplicateEmailRegistration() throws Exception {
        RegisterRequest signUpRequest = new RegisterRequest("Tony Qing", "tony@example.com", "password");

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isConflict());

        assertThat(userRepository.findAll()).hasSize(1);
    }

    @Test
    void shouldRejectLoginForUnknownUser() throws Exception {
        LoginRequest loginRequest = new LoginRequest("missing@example.com", "password");

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());

        assertThat(sessionRepository.findAll()).isEmpty();
    }
}