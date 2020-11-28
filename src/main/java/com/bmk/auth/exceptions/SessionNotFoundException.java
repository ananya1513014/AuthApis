package com.bmk.auth.exceptions;

public class SessionNotFoundException extends Exception{
    public SessionNotFoundException(){
        super("Session not found for user. Invalid userId or user is not logged on any device");
    }
}