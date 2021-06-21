package com.bmk.auth.repository;

import com.bmk.auth.bo.User;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface UserRepo extends CrudRepository<User, String> {
    User findByEmail(String email);
    User findByStaticUserId(Long userId);
    User[] findAllByStaticUserIdAfter(Long id);
    Optional<User> findByPhone(String phone);
}