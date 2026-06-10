package com.tonyqing.authentication.auth.mapper;
import java.util.List;
import java.util.stream.Collectors;


import com.tonyqing.authentication.auth.dto.RegisterRequest;
import com.tonyqing.authentication.auth.dto.RegisterResponse;
import com.tonyqing.authentication.auth.entity.User;

public class UserMapper {
    public static User toEntity(RegisterRequest userRequest) {
        User user = new User(userRequest.name(), userRequest.email(), userRequest.password());
        return user;
    }

    public static RegisterResponse toResponse(User user) {
        return new RegisterResponse(user.getId(), user.getDisplayName(), user.getEmail());
    }

    public static List<RegisterResponse> toResponse(List<User> users) {
        return users.stream().map(UserMapper::toResponse).collect(Collectors.toList());
    }
}
