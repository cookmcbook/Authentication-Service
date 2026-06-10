package com.tonyqing.authentication.auth.mapper;
import java.util.List;
import java.util.stream.Collectors;


import com.tonyqing.authentication.auth.dto.UserRequest;
import com.tonyqing.authentication.auth.dto.UserResponse;
import com.tonyqing.authentication.auth.entity.User;

public class UserMapper {
    public static User toEntity(UserRequest userRequest) {
        User user = new User(userRequest.name(), userRequest.email());
        return user;
    }

    public static UserResponse toResponse(User user) {
        return new UserResponse(user.getId(), user.getDisplayName(), user.getEmail());
    }

    public static List<UserResponse> toResponse(List<User> users) {
        return users.stream().map(UserMapper::toResponse).collect(Collectors.toList());
    }
}
