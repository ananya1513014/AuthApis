package com.bmk.auth.controller;

import com.bmk.auth.exceptions.InvalidTokenException;
import com.bmk.auth.exceptions.InvalidUserDetailsException;
import com.bmk.auth.service.TokenService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.bmk.auth.bo.Response;
import com.bmk.auth.bo.User;
import com.bmk.auth.exceptions.DuplicateUserException;
import com.bmk.auth.request.CredBuilder;
import com.bmk.auth.request.UserBuilder;
import com.bmk.auth.service.UserService;
import com.bmk.auth.util.Constants;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping(Constants.USER_ENDPOINT)
@RestController
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    private final UserService userService;
    private final TokenService tokenService;
    private static ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public UserController(UserService userService, TokenService tokenService) {
        this.userService = userService;
        this.tokenService = tokenService;
    }

    @PostMapping("/signup")
    private ResponseEntity createUser(@RequestBody String param){
        logger.info("Signup", param);

        try{
            User user = new User(objectMapper.readValue(param, UserBuilder.class));
            if(user.getEmail()==null||user.getEmail().equals("")||user.getPassword()==null||user.getPassword().length()<8) throw new InvalidUserDetailsException();
            userService.addUser(user);
            return ResponseEntity.ok(new Response("200", "Sign up success"));
        } catch (DuplicateUserException exp){
            logger.info("Duplicate User Exception encountered for : ", param);
            return ResponseEntity.status(HttpStatus.EXPECTATION_FAILED).body(new Response("412", "User exists with the specified ID"));
        } catch (JsonProcessingException e) {
            logger.info("Json Processing Exception encountered for : ", param);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("400", "Request format is wrong"));
        } catch (InvalidUserDetailsException e) {
            logger.info("Invalid user details : ", param);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("406", "Username/Password is not as expected"));
        }
    }

    @PostMapping("/singin")
    private ResponseEntity login(@RequestBody String param){
        logger.info(param, " Signin");
        try{
            CredBuilder credBuilder  = objectMapper.readValue(param, CredBuilder.class);
            userService.verifyCred(credBuilder);
            String token = tokenService.getToken(credBuilder.getEmail());
            HttpHeaders responseHeaders = new HttpHeaders();
            responseHeaders.set("token", token);
            return new ResponseEntity(new Response("200", "Login Success"), responseHeaders, HttpStatus.OK);
        } catch (AssertionError e) {
            logger.info("Invalid Credentials");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("401", "Invalid credentials"));
        } catch (JsonProcessingException e) {
            logger.info("Json Processing Exception encountered for : ", param);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("400", "Request format is wrong"));
        }
    }

    @PostMapping("/authorize")
    private ResponseEntity authorize(@RequestHeader("token") String token){
        try {
            tokenService.authorize(tokenService.getUserId(token), token);
            logger.info("Request is authorized");
            return ResponseEntity.ok(new Response("200", "Authorized"));
        } catch (AssertionError | InvalidTokenException e){
            logger.info("Invalid Token Received");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("401", "Invalid Token"));
        }
    }
}