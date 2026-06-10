package com.tonyqing.authentication.auth.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.tonyqing.authentication.auth.entity.User;
import com.tonyqing.authentication.auth.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataSeeder {

    @Bean
    CommandLineRunner seedAdminUser(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            boolean hasUsers = userRepository.count() > 0;

            if (!hasUsers) {
                User user = new User("Admin","admin@example.com", passwordEncoder.encode("password"));
                userRepository.save(user);
            }
        };
    }
}