package com.bmk.auth.controller;

import com.bmk.auth.cache.OtpCache;
import com.bmk.auth.exceptions.*;
import com.bmk.auth.request.OtpVal;
import com.bmk.auth.request.SignupVal;
import com.bmk.auth.response.out.DeviceIdResponse;
import com.bmk.auth.response.out.LoginResponse;
import com.bmk.auth.response.out.UserListResponse;
import com.bmk.auth.service.TokenService;
import com.bmk.auth.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.bmk.auth.response.out.Response;
import com.bmk.auth.bo.User;
import com.bmk.auth.request.LoginRequest;
import com.bmk.auth.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.web.bind.annotation.*;

import javax.validation.ConstraintViolationException;

@RequestMapping(Constants.USER_ENDPOINT)
@RestController
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService;
    private final TokenService tokenService;
    private static ObjectMapper objectMapper = new ObjectMapper();
    private static final String ENCRYPT_KEY_A = System.getenv("encryptKeyA");
    private static final String ENCRYPT_KEY_B = System.getenv("encryptKeyB");
    private final static String AES_SECRET = System.getenv("aesSecret");

    @Autowired
    public UserController(UserService userService, TokenService tokenService) {
        this.userService = userService;
        this.tokenService = tokenService;
    }

    @PostMapping("/signup")
    private ResponseEntity createUser(@RequestBody String param, @RequestHeader(required = false) String token) throws Throwable {
        try {
            User user = (objectMapper.readValue(param, User.class));
            logger.info(objectMapper.readValue(param, User.class).toString());

            Helper.validateSignup(user, token);
            user.setPassword(Security.encrypt(user.getPassword(), AES_SECRET));
            user = userService.addUser(user);

            return ResponseEntity.ok(new Response("200", "Sign up success:" + user.getStaticUserId()));
        } catch (TransactionSystemException e) {
            throw e.getCause().getCause();
        }
    }

    @PostMapping("/singin")
    private ResponseEntity login(@RequestBody String param) throws InvalidUserDetailsException, JsonProcessingException {
        logger.info(param, " Signin");
            LoginRequest loginRequest = objectMapper.readValue(param, LoginRequest.class);
            if(loginRequest.getEmail()==null|| loginRequest.getPassword()==null) throw new InvalidUserDetailsException();
            userService.verifyCred(loginRequest);
            User user = userService.getUserByEmail(loginRequest.getEmail());
            String token = tokenService.getToken(user);
            HttpHeaders responseHeaders = new HttpHeaders();
            responseHeaders.set("token", token);
            return new ResponseEntity(new LoginResponse("200", "Login Success", token), responseHeaders, HttpStatus.OK);
    }

    @PostMapping("/authorize")
    private ResponseEntity authorize(@RequestHeader("token") String token, @RequestHeader String apiType) throws InvalidTokenException {
            tokenService.authorizeApi(token, apiType);
            return ResponseEntity.ok(new Response("200", "Authorized :"+tokenService.getUserId(token)));
    }

    @GetMapping("/deviceId")
    private ResponseEntity getDeviceId(@RequestParam Long userId){
        try {
            String deviceId = tokenService.getDeviceId(userId);
            return ResponseEntity.ok(new DeviceIdResponse("200", "Success", deviceId));
        } catch (SessionNotFoundException e){
              return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(new Response("406", "Session not found"));
        }
    }

    @GetMapping("/details")
    private ResponseEntity getUserDetails(@RequestHeader String token, @RequestParam(required = false) String userId) throws InvalidTokenException, InvalidUserDetailsException {
        userId = userId==null ? tokenService.getUserId(token) : userId;
        return ResponseEntity.ok(new Response("200", userService.getUserById(Long.parseLong(userId))));
    }

    @GetMapping("/all")
    private ResponseEntity getAllUsers(@RequestHeader String token) throws InvalidTokenException {
        tokenService.authorizeApi(token, "alpha");
        return ResponseEntity.ok(new UserListResponse("200", "Success", userService.getAllUsers()));
    }

    @PostMapping("verifyUniqueDetails")
    private  ResponseEntity validateDetails(@RequestBody String param) throws JsonProcessingException, DuplicateUserException {
        SignupVal signupVal = objectMapper.readValue(param, SignupVal.class);
        userService.isNumberEmailAvailable(signupVal.getPhone(), signupVal.getEmail());
        RestClient.sendOtp(signupVal.getPhone());
        return  ResponseEntity.status(HttpStatus.OK).body(new LoginResponse("200", "Success", Security.encrypt(signupVal.getEmail()+"|"+signupVal.getPhone(), ENCRYPT_KEY_A)));
    }

    @PutMapping("validateOtp")
    private ResponseEntity validateOtp(@RequestHeader String token, @RequestBody String param) throws JsonProcessingException, InvalidOtpException {
        OtpVal otpVal = objectMapper.readValue(param, OtpVal.class);
        String phone = Security.decrypt(token, ENCRYPT_KEY_A).split("\\|")[1];
        if(OtpCache.map.get(phone)!=otpVal.getOtp()) throw new InvalidOtpException();
        return  ResponseEntity.status(HttpStatus.OK).body(new LoginResponse("200", "Success", Security.encrypt(token, ENCRYPT_KEY_B)));
    }
}