package com.bmk.auth.exceptions;

import com.bmk.auth.response.out.Response;
import com.twilio.exception.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(InvalidOtpException.class)
    public ResponseEntity exceptionHandler(InvalidOtpException e) {
        logger.info(e);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("400", "Invalid Otp"));
    }

    @ExceptionHandler(DuplicateUserException.class)
    public ResponseEntity exceptionHandler(DuplicateUserException e) {
        logger.info(e);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("400", e.getMessage()));
    }

    @ExceptionHandler(ApiException.class)
    public ResponseEntity exceptionHandler(ApiException e) {
        logger.info(e);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("400", e.getMessage()));
    }
}
