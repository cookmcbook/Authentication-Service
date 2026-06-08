package com.tonyqing.authentication.auth.service;
import com.tonyqing.authentication.auth.dto.UserResponse;
import com.tonyqing.authentication.auth.repository.UserRepository;

import org.springframework.stereotype.Service;
import com.tonyqing.authentication.auth.dto.UserRequest;
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
    public UserResponse createUser(UserRequest userRequest) {
        User user = userRepository.save(UserMapper.toEntity(userRequest));
        return UserMapper.toResponse(user);
    }

    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream().map(UserMapper::toResponse).toList();
    }

    public UserResponse getUserById(Long id) {
        User user = userRepository.findById(id)
            .orElseThrow(() -> new UserNotFoundException(id));

        return UserMapper.toResponse(user);
    }

    public UserResponse updateUser(Long id, UserRequest request) {
        User user = userRepository.findById(id)
            .orElseThrow(() -> new UserNotFoundException(id));

        user.setName(request.name());
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
