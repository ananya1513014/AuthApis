package com.bmk.auth.repository;

import com.bmk.auth.bo.AuthToken;
import org.springframework.data.repository.CrudRepository;

public interface TokenRepo extends CrudRepository<AuthToken, String> {
    AuthToken findByEmail(String email);
}