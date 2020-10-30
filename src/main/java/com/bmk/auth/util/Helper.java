package com.bmk.auth.util;

public class Helper {
    public static int generateOtp() {
        return  (int)(Math.random()*1000000) % 1000000;
    }
}