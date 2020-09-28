package com.bmk.auth.controller;

import com.bmk.auth.bo.AuthToken;
import com.bmk.auth.exceptions.InvalidTokenException;
import com.bmk.auth.exceptions.InvalidUserDetailsException;
import com.bmk.auth.exceptions.SessionNotFoundException;
import com.bmk.auth.response.out.DeviceIdResponse;
import com.bmk.auth.response.out.LoginResponse;
import com.bmk.auth.service.TokenService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.bmk.auth.response.out.Response;
import com.bmk.auth.bo.User;
import com.bmk.auth.exceptions.DuplicateUserException;
import com.bmk.auth.request.LoginRequest;
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
            logger.info(objectMapper.readValue(param, UserBuilder.class).toString());

            User user = new User(objectMapper.readValue(param, UserBuilder.class));
            if(user.getEmail()==null||user.getEmail().equals("")||user.getPassword()==null||user.getPassword().length()<8) throw new InvalidUserDetailsException();

            if(user.getUserType()==null)    user.setUserType(Constants.CLIENT);

            if(user.getUserType().equals(Constants.ADMIN)||user.getUserType().equals(Constants.SUPERUSER)){
                tokenService.authorizeApi(token, Constants.SUPERUSER_ACCESS);
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
            LoginRequest loginRequest = objectMapper.readValue(param, LoginRequest.class);
            if(loginRequest.getEmail()==null|| loginRequest.getPassword()==null) throw new InvalidUserDetailsException();
            userService.verifyCred(loginRequest);
            User user = userService.getUserByEmail(loginRequest.getEmail());
            String token = tokenService.saveAuthToken(new AuthToken(user.getStaticUserId().toString(), tokenService.getToken(user), loginRequest.getDeviceId())).getToken();
            HttpHeaders responseHeaders = new HttpHeaders();
            responseHeaders.set("token", token);
            return new ResponseEntity(new LoginResponse("200", "Login Success", token), responseHeaders, HttpStatus.OK);
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

    @GetMapping("/deviceId")
    private ResponseEntity getDeviceId(@RequestParam Long userId){
        try {
            String deviceId = tokenService.getDeviceId(userId);
            return ResponseEntity.ok(new DeviceIdResponse("200", "Success", deviceId));
        } catch (SessionNotFoundException e){
              return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(new Response("406", "Session not found"));
        } catch(Exception e){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("510", "Unknown Expception occured."));
        }
    }

    @GetMapping("/details")
    private ResponseEntity getUserDetails(@RequestHeader String token) {
        try {
            String userId = tokenService.getUserId(token);
            User user = userService.getUserById(Long.parseLong(userId));
            user.setPassword("*HIDDEN*");
            return ResponseEntity.ok(new Response("200", user));
        } catch(InvalidTokenException | InvalidUserDetailsException e){
            logger.info("Invalid token recieved");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("406", "Invalid token received"));
        }
    }
}