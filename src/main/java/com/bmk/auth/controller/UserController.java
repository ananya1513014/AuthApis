package com.bmk.auth.controller;

import com.bmk.auth.exceptions.*;
import com.bmk.auth.request.OtpVal;
import com.bmk.auth.request.PasswordReset;
import com.bmk.auth.request.SignupVal;
import com.bmk.auth.response.out.DeviceIdResponse;
import com.bmk.auth.response.out.LoginResponse;
import com.bmk.auth.response.out.UserListResponse;
import com.bmk.auth.util.TokenUtil;
import com.bmk.auth.util.*;
import com.bmk.auth.response.out.Response;
import com.bmk.auth.bo.User;
import com.bmk.auth.request.LoginRequest;
import com.bmk.auth.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RequestMapping(Constants.USER_ENDPOINT)
@RestController
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService;
    TokenUtil tokenUtil = new TokenUtil(); //Do not remove
    private static final String ENCRYPT_KEY_A = System.getenv("encryptKeyA");
    private static final String ENCRYPT_KEY_B = System.getenv("encryptKeyB");
    private static final String AES_SECRET = System.getenv("aesSecret");

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signup")
    private ResponseEntity<Response> createUser(@RequestBody @Valid User user, @RequestHeader(required = false) String token) throws Throwable {
        try {
            logger.info(user.toString());

            Helper.validateSignup(user, token);
            user.setPassword(Security.encrypt(user.getPassword(), AES_SECRET));
            user = userService.addUser(user);

            return ResponseEntity.ok(new Response("200", "Sign up success:" + user.getStaticUserId()));
        } catch (TransactionSystemException e) {
            throw e.getCause().getCause();
        }
    }

    @PostMapping("/singin")
    private ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest loginRequest, Errors errors) throws InvalidUserDetailsException, InvalidRequestBody {
        if(errors.hasErrors()) throw new InvalidRequestBody(errors);
        logger.info(loginRequest.toString(), " Signin");
        userService.verifyCred(loginRequest);
        User user = userService.getUserByEmail(loginRequest.getEmail());
        user.setDeviceId(loginRequest.getDeviceId());
        userService.addUser(user);

        String token = TokenUtil.getToken(user);
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.set("token", token);
        return new ResponseEntity<>(new LoginResponse("200", "Login Success", token), responseHeaders, HttpStatus.OK);
    }

    @PostMapping("/authorize")
    private ResponseEntity<Response> authorize(@RequestHeader("token") String token, @RequestHeader String apiType) throws InvalidTokenException {
        TokenUtil.authorizeApi(token, apiType);
        return ResponseEntity.ok(new Response("200", "Authorized :"+ TokenUtil.getUserId(token)));
    }

    @GetMapping("/deviceId")
    private ResponseEntity<DeviceIdResponse> getDeviceId(@RequestParam Long userId) throws InvalidUserDetailsException {
        String deviceId = userService.getUserById(userId).getDeviceId();
        return ResponseEntity.ok(new DeviceIdResponse("200", "Success", deviceId));
    }

    @GetMapping("/details")
    private ResponseEntity<Response> getUserDetails(@RequestHeader(required = false) String token, @RequestParam(required = false) Long userId) throws InvalidTokenException, InvalidUserDetailsException {
        userId = userId==null ? TokenUtil.getUserId(token) : userId;
        return ResponseEntity.ok(new Response("200", userService.getUserById(userId)));
    }

    @GetMapping("/all")
    private ResponseEntity<UserListResponse> getAllUsers(@RequestHeader String token) throws InvalidTokenException {
        TokenUtil.authorizeApi(token, "alpha");
        return ResponseEntity.ok(new UserListResponse("200", "Success", userService.getAllUsers()));
    }

    @PostMapping("verifyUniqueDetails")
    private ResponseEntity<LoginResponse> validateDetails(@RequestBody SignupVal signupVal) throws DuplicateUserException {
        userService.isNumberEmailAvailable(signupVal.getPhone(), signupVal.getEmail());
        int otp = SmsUtil.sendNewUserOtp(signupVal.getPhone());
        return  ResponseEntity.status(HttpStatus.OK).body(new LoginResponse("200", "Success", Security.encrypt(signupVal.getEmail()+"|"+signupVal.getPhone()+"|"+otp, ENCRYPT_KEY_A)));
    }

    @PutMapping("validateOtp")
    private ResponseEntity<LoginResponse> validateOtp(@RequestHeader String token, @RequestBody OtpVal otpVal) throws InvalidOtpException {
        int otp = Integer.parseInt(Security.decrypt(token, ENCRYPT_KEY_A).split("\\|")[2]);
        if(otp!=otpVal.getOtp()) throw new InvalidOtpException();
        return  ResponseEntity.status(HttpStatus.OK).body(new LoginResponse("200", "Success", Security.encrypt(token, ENCRYPT_KEY_B)));
    }

    @PutMapping("forgotPassword")
    private ResponseEntity<LoginResponse> forgotPassword(@RequestParam(required = false) String email, @RequestParam(required = false) String phone) throws Exception {
        if(phone==null&&email==null)    throw new Exception();
        User user = phone!=null?userService.getUserByPhone("+"+phone.trim())[0]:userService.getUserByEmail(email);
        int otp = SmsUtil.sendPasswordResetOtp(user.getPhone());
        return  ResponseEntity.status(HttpStatus.OK).body(new LoginResponse("200", "Success", Security.encrypt(user.getEmail()+"|"+user.getPhone()+"|"+otp, ENCRYPT_KEY_A)));
    }

    @PutMapping("resetPassword")
    private ResponseEntity<LoginResponse> resetPassword(@RequestHeader String token, @RequestBody PasswordReset passwordReset, @RequestParam(required = false) String type) throws InvalidTokenException, InvalidUserDetailsException {
        User user = StringUtil.equals(type, "forgot")?userService.getUserByEmail(Security.decrypt(Security.decrypt(token, ENCRYPT_KEY_B), ENCRYPT_KEY_A).split("\\|")[0]):userService.getUserById(TokenUtil.authorizeApi(token, "delta"));
        user.setPassword(Security.encrypt(passwordReset.getPassword(), AES_SECRET));
        userService.addUser(user);
        token = TokenUtil.getToken(user);
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.set("token", token);
        return new ResponseEntity<>(new LoginResponse("200", "Password Reset Success", token), responseHeaders, HttpStatus.OK);
    }
}