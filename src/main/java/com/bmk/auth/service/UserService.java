package com.bmk.auth.service;

import com.bmk.auth.bo.User;
import com.bmk.auth.exceptions.DuplicateUserException;
import com.bmk.auth.exceptions.InvalidUserDetailsException;
import com.bmk.auth.repository.UserRepo;
import com.bmk.auth.request.LoginRequest;
import com.bmk.auth.util.Security;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private static UserRepo userRepo;
    private final static String AES_SECRET = System.getenv("aesSecret");
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    public UserService(UserRepo userRepo){
        this.userRepo = userRepo;
    }

    public User addUser(User user) throws DuplicateUserException {
        logger.info("Adding new user");
        if(userRepo.findByEmail(user.getEmail()) != null)
            throw new DuplicateUserException(user.getEmail());
        return userRepo.save(user);
    }

    public UserService verifyCred(LoginRequest loginRequest) throws InvalidUserDetailsException {
        logger.info("Verifying Credentials");
        User user = userRepo.findByEmail(loginRequest.getEmail());
        if(user==null)  throw new InvalidUserDetailsException();
        Assert.assertEquals(user.getPassword(), Security.encrypt(loginRequest.getPassword(), AES_SECRET));
        logger.info("Credentials verified successfully");
        return this;
    }

    public Long getStaticUserId(String email) {
        logger.info("Searching for static userid for email", email);
        return userRepo.findByEmail(email).getStaticUserId();
    }

    public User getUserByEmail(String email){
        return userRepo.findByEmail(email);
    }

    public User getUserById(Long userId) throws InvalidUserDetailsException {
        User user =  userRepo.findByStaticUserId(userId);
        if(user==null)  throw new InvalidUserDetailsException();
        return user;
    }

    public User[] getAllUsers() {
        return userRepo.findAllByStaticUserIdAfter(Long.parseLong("0"));
    }
}