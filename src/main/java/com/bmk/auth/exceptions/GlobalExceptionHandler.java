package com.bmk.auth.exceptions;

import com.bmk.auth.response.out.ErrorResponse;
import com.bmk.auth.response.out.InvalidFieldResponse;
import com.bmk.auth.response.out.Response;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.twilio.exception.ApiException;
import org.hibernate.validator.internal.engine.ConstraintViolationImpl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import java.util.ArrayList;
import java.util.List;

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

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity exceptionHandler(InvalidTokenException e) {
        logger.info(e);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("400", "Invalid token"));
    }

    @ExceptionHandler(InvalidUserDetailsException.class)
    public ResponseEntity exceptionHandler(InvalidUserDetailsException e) {
        logger.info(e);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("400", "Invalid user details"));
    }

    @ExceptionHandler(JsonProcessingException.class)
    public ResponseEntity exceptionHandler(JsonProcessingException e) {
        logger.info(e);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("400", "Invalid request format"));
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity exceptionHandler(ConstraintViolationException e) {
        logger.info(e.getConstraintViolations().toString());
        Object[] constraintViolations = e.getConstraintViolations().toArray();
        List<InvalidFieldResponse> invalidFieldResponseList = new ArrayList<>();
        for (int i=0; i<constraintViolations.length; i++) {
            ConstraintViolationImpl constraintViolation = (ConstraintViolationImpl)constraintViolations[i];
            InvalidFieldResponse invalidFieldResponse = new InvalidFieldResponse(constraintViolation.getPropertyPath().toString(), constraintViolation.getMessage());
            invalidFieldResponseList.add(invalidFieldResponse);
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse("400", "Request has some invalid values", invalidFieldResponseList));
    }

    @ExceptionHandler(SessionNotFoundException.class)
    private ResponseEntity exceptionHandler(SessionNotFoundException e) {
        logger.info(e);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response("400", e.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity exceptionHandler(Exception e) {
        logger.info(e);
        logger.info(e.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new Response("500", "Encountered unknown error"));
    }
}