package com.bmk.auth.exceptions;

public class InvalidTokenException extends Exception{
    public InvalidTokenException(){
        super("Invalid Token");
    }
}
