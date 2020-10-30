package com.bmk.auth.exceptions;

public class InvalidOtpException extends Exception {
    public InvalidOtpException() {
        super("Invalid otp");
    }
}
