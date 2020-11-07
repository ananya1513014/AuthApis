package com.bmk.auth.repository;

import com.bmk.auth.bo.User;
import org.springframework.data.repository.CrudRepository;

public interface UserRepo extends CrudRepository<User, String> {
    User findByEmail(String email);
    User findByStaticUserId(Long userId);
    User[] findAllByStaticUserIdAfter(Long id);
    User[] findByPhone(String phone);
}