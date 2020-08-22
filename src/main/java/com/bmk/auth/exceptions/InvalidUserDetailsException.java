package com.bmk.auth.exceptions;

public class InvalidUserDetailsException extends Exception{
    public InvalidUserDetailsException(){
        super("Invalid user  details");
    }
}
