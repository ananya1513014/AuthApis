package com.bmk.auth.service;

import com.bmk.auth.bo.User;
import com.bmk.auth.exceptions.DuplicateUserException;
import com.bmk.auth.exceptions.InvalidUserDetailsException;
import com.bmk.auth.repository.UserRepo;
import com.bmk.auth.request.LoginRequest;
import com.bmk.auth.util.Security;
import com.bmk.auth.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private static UserRepo userRepo;
    private static final String AES_SECRET = System.getenv("aesSecret");
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    public UserService(UserRepo userRepo){
        this.userRepo = userRepo;
    }

    public User addUser(User user) {
        logger.info("Adding new user");
        return userRepo.save(user);
    }

    public UserService verifyCred(LoginRequest loginRequest) throws InvalidUserDetailsException {
        User user = userRepo.findByEmail(loginRequest.getEmail());
        if(user==null)  throw new InvalidUserDetailsException();
        boolean isValid = StringUtil.equals(user.getPassword(), Security.encrypt(loginRequest.getPassword(), AES_SECRET));
        if(!isValid) throw new InvalidUserDetailsException();
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

    @Cacheable("user")
    public User getUserById(Long userId) throws InvalidUserDetailsException {
        User user =  userRepo.findByStaticUserId(userId);
        if(user==null)  throw new InvalidUserDetailsException();
        user.setPassword("*HIDDEN*");
        return user;
    }

    public User[] getAllUsers() {
        return userRepo.findAllByStaticUserIdAfter(Long.parseLong("0"));
    }

    public User[] getUserByPhone(String phoneNumber) {
        return userRepo.findByPhone(phoneNumber);
    }

    public void isNumberEmailAvailable(String phone, String email) throws DuplicateUserException {
        if((getUserByPhone(phone).length!=0||getUserByEmail(email)!=null)&&!phone.equals("+918077019693"))
            throw new DuplicateUserException("User with given email/phone number  exists");
    }
}