package com.spring.security.video.course.practice.auth.dao;

import com.spring.security.video.course.practice.auth.model.User;

import java.util.Optional;

public interface UserDao {
    Optional<User> getByUsername(String username);
}
