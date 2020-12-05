package com.bmk.auth.util;

public class SmsUtil {

    public static int sendPasswordResetOtp(String phoneNumber) {
        int otp = Helper.generateOtp();
        String message = "Your OTP for BookMyKainchi Password reset is " + otp + ". Kindly do not share this OTP with anyone";
        RestClient.sendOtp(phoneNumber, message);
        return otp;
    }

    public static int sendNewUserOtp(String phoneNumber) {
        int otp = Helper.generateOtp();
        String message = "Welcome to BookMyKainchi!" + otp + " is your OTP for registering your account. Kindly do not share this OTP with anyone";
        RestClient.sendOtp(phoneNumber, message);
        return otp;
    }
}