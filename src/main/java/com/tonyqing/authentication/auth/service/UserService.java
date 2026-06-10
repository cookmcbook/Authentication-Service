package com.tonyqing.authentication.auth.service;
import com.tonyqing.authentication.auth.dto.RegisterResponse;
import com.tonyqing.authentication.auth.repository.UserRepository;

import org.springframework.stereotype.Service;
import com.tonyqing.authentication.auth.dto.RegisterRequest;
import com.tonyqing.authentication.auth.entity.User;
import com.tonyqing.authentication.auth.mapper.UserMapper;
import com.tonyqing.authentication.auth.exception.UserNotFoundException;

import java.util.List;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    public RegisterResponse createUser(RegisterRequest userRequest) {
        User user = userRepository.save(UserMapper.toEntity(userRequest));
        return UserMapper.toResponse(user);
    }

    public List<RegisterResponse> getAllUsers() {
        return userRepository.findAll().stream().map(UserMapper::toResponse).toList();
    }

    public RegisterResponse getUserById(Long id) {
        User user = userRepository.findById(id)
            .orElseThrow(() -> new UserNotFoundException(id));

        return UserMapper.toResponse(user);
    }

    public RegisterResponse updateUser(Long id, RegisterRequest request) {
        User user = userRepository.findById(id)
            .orElseThrow(() -> new UserNotFoundException(id));

        user.setDisplayName(request.name());
        user.setEmail(request.email());

        User savedUser = userRepository.save(user);
        return UserMapper.toResponse(savedUser);
    }

    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new UserNotFoundException(id);
        }

        userRepository.deleteById(id);
    }
    
}
