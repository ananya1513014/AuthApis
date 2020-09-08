package com.bmk.auth.controller;

import com.bmk.auth.exceptions.InvalidTokenException;
import com.bmk.auth.exceptions.InvalidUserDetailsException;
import com.bmk.auth.service.TokenService;
import com.bmk.auth.util.Security;
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
    private ResponseEntity createUser(@RequestBody String param, @RequestHeader String token){
        logger.info("Signup", param);

        try{
            User user = new User(objectMapper.readValue(param, UserBuilder.class));
            if(user.getEmail()==null||user.getEmail().equals("")||user.getPassword()==null||user.getPassword().length()<8) throw new InvalidUserDetailsException();

            if(user.getUserType()==null){
                user.setUserType(Constants.CLIENT);
            } else if(user.getUserType().equals(Constants.MERCHANT)){
                tokenService.authorizeApi(token, Constants.ADMIN_ACCESS);
            } else if(user.getUserType().equals(Constants.ADMIN)||user.getUserType().equals(Constants.SUPERUSER)){
                tokenService.authorizeApi(token, Constants.SUPERUSER_ACCESS);
            }else {
                user.setUserType(Constants.CLIENT);
            }
            userService.addUser(user);
            return ResponseEntity.ok(new Response("200", "Sign up success"));
        } catch (DuplicateUserException e){
            logger.info("Duplicate User Exception encountered for : ", param, e);
            return ResponseEntity.status(HttpStatus.EXPECTATION_FAILED).body(new Response("412", "User exists with the specified ID"));
        }catch (InvalidUserDetailsException e) {
            logger.info("Invalid user details : ", param, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("406", "Username/Password is not as expected"));
        } catch (InvalidTokenException e) {
            logger.info("User cannot create user with specified user type", param, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("406", "User cannot create user with specified user type"));
        } catch (JsonProcessingException e) {
            logger.info("Json Processing Exception encountered for : ", param, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("400", "Request format is wrong"));
        }
    }

    @PostMapping("/singin")
    private ResponseEntity login(@RequestBody String param){
        logger.info(param, " Signin");
        try{
            CredBuilder credBuilder  = objectMapper.readValue(param, CredBuilder.class);
            if(credBuilder.getEmail()==null||credBuilder.getPassword()==null) throw new InvalidUserDetailsException();
            userService.verifyCred(credBuilder);
            String token = tokenService.getToken(userService.getUserByEmail(credBuilder.getEmail()));
            HttpHeaders responseHeaders = new HttpHeaders();
            responseHeaders.set("token", token);
            return new ResponseEntity(new Response("200", "Login Success"), responseHeaders, HttpStatus.OK);
        } catch (AssertionError | InvalidUserDetailsException e) {
            logger.info("Invalid Credentials");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("401", "Invalid credentials"));
        } catch (JsonProcessingException e) {
            logger.info("Json Processing Exception encountered for : ", param);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("400", "Request format is wrong"));
        }
    }

    @PostMapping("/authorize")
    private ResponseEntity authorize(@RequestHeader("token") String token, @RequestHeader String apiType){
        try {
            tokenService.authorizeApi(token, apiType);
            logger.info("Request is authorized");
            return ResponseEntity.ok(new Response("200", "Authorized :"+tokenService.getUserId(token)));
        } catch (AssertionError | InvalidTokenException e){
            logger.info("Invalid Token Received");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("401", "Invalid Token"));
        }
    }
}