package com.tonyqing.authentication.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tonyqing.authentication.auth.entity.User;

public interface UserRepository extends JpaRepository<User, Long>{
    
}
