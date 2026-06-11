package com.tonyqing.authentication.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tonyqing.authentication.auth.dto.LoginRequest;
import com.tonyqing.authentication.auth.dto.LoginResponse;
import com.tonyqing.authentication.auth.dto.RegisterRequest;
import com.tonyqing.authentication.auth.dto.TokenResponse;

import com.tonyqing.authentication.auth.entity.User;
import com.tonyqing.authentication.auth.repository.UserRepository;

import jakarta.servlet.http.Cookie;

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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;

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
        void shouldRegisterLoginRefreshAndAccessProtectedRoute() throws Exception {
                RegisterRequest signUpRequest = new RegisterRequest("Tony Qing", "tony@example.com", "password");

                mockMvc.perform(post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(signUpRequest)))
                                .andExpect(status().isCreated());

                LoginRequest loginRequest = new LoginRequest("tony@example.com", "password");

                MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andExpect(cookie().exists("refreshToken"))
                                .andReturn();

                String loginBody = loginResult.getResponse().getContentAsString();
                TokenResponse loginResponse = objectMapper.readValue(loginBody, TokenResponse.class);

                String accessToken = loginResponse.accessToken();
                assertThat(accessToken).isNotBlank();

                Cookie refreshCookie = loginResult.getResponse().getCookie("refreshToken");

                MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                                .cookie(refreshCookie))
                                .andExpect(status().isOk())
                                .andReturn();

                String refreshBody = refreshResult.getResponse().getContentAsString();
                TokenResponse refreshResponse = objectMapper.readValue(refreshBody, TokenResponse.class);

                String refreshedAccessToken = refreshResponse.accessToken();
                assertThat(refreshedAccessToken).isNotBlank();

                mockMvc.perform(get("/api/auth/me")
                                .header("Authorization", "Bearer " + refreshedAccessToken))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.email").value("tony@example.com"))
                                .andExpect(jsonPath("$.displayName").value("Tony Qing"));
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

        @Test
        void shouldLogoutAndClearRefreshCookie() throws Exception {
                RegisterRequest signUpRequest = new RegisterRequest("Tony Qing", "tony@example.com", "password");

                mockMvc.perform(post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(signUpRequest)))
                                .andExpect(status().isCreated());

                LoginRequest loginRequest = new LoginRequest("tony@example.com", "password");

                MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andExpect(cookie().exists("refreshToken"))
                                .andReturn();

                Cookie refreshCookie = loginResult.getResponse().getCookie("refreshToken");

                assertThat(refreshCookie).isNotNull();
                assertThat(sessionRepository.findByRefreshToken(refreshCookie.getValue())).isPresent();

                mockMvc.perform(post("/api/auth/logout")
                                .cookie(refreshCookie))
                                .andExpect(status().isNoContent())
                                .andExpect(cookie().maxAge("refreshToken", 0));

                assertThat(sessionRepository.findByRefreshToken(refreshCookie.getValue())).isEmpty();
        }
}