package com.bmk.auth.exceptions;

public class DuplicateUserException extends Exception{
    public DuplicateUserException(String exc) {
        super(exc);
    }
}