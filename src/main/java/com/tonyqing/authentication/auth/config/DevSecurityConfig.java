package com.tonyqing.authentication.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.tonyqing.authentication.auth.security.SessionTokenFilter;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@Profile("dev")
public class DevSecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, SessionTokenFilter sessionTokenFilter) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/swagger-ui.html"
                        ).permitAll()
                        .requestMatchers("/api/auth/register", "/api/auth/login", "/api/auth/refresh", "/api/auth/logout", "/api/auth/forgot-password", "/api/auth/reset-password").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form.disable())
                .httpBasic(httpBasic -> httpBasic.disable())
                .exceptionHandling(
                        ex -> ex.authenticationEntryPoint((request, response, authException) -> 
                        {
                                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        })
                )
                .addFilterBefore(sessionTokenFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
