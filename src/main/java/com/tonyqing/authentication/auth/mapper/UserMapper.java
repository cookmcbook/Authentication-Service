package com.tonyqing.authentication.auth.mapper;
import java.util.List;
import java.util.stream.Collectors;


import com.tonyqing.authentication.auth.dto.UserRequest;
import com.tonyqing.authentication.auth.dto.UserResponse;
import com.tonyqing.authentication.auth.entity.User;

public class UserMapper {
    public static User toEntity(UserRequest userRequest) {
        User user = new User();
        user.setName(userRequest.name());
        user.setEmail(userRequest.email());
        return user;
    }

    public static UserResponse toResponse(User user) {
        return new UserResponse(user.getId(), user.getName(), user.getEmail());
    }

    public static List<UserResponse> toResponse(List<User> users) {
        return users.stream().map(UserMapper::toResponse).collect(Collectors.toList());
    }
}
