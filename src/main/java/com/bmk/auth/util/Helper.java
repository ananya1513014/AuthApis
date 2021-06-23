package com.bmk.auth.util;

import com.bmk.auth.bo.User;
import com.bmk.auth.exceptions.InvalidTokenException;

import java.text.DecimalFormat;
import java.util.Random;

public class Helper {

    private static final String ENCRYPT_KEY_A = System.getenv("encryptKeyA");
    private static final String ENCRYPT_KEY_B = System.getenv("encryptKeyB");

    public static String generateOtp() {
        String otp= new DecimalFormat("00000").format(new Random().nextInt(99999));
        return otp;
    }

    public static void validateSignup(User user, String token) throws InvalidTokenException {
        if(!StringUtil.contains(Security.decrypt(Security.decrypt(token, ENCRYPT_KEY_B), ENCRYPT_KEY_A),user.getEmail()+"|"+user.getPhone())) throw new InvalidTokenException();
    }
}