package com.bmk.auth.exceptions;

import lombok.Data;
import org.springframework.validation.Errors;

@Data
public class InvalidRequestBody extends Exception{

    Errors errors;
    public InvalidRequestBody(Errors errors) {
        super(errors.toString());
        this.errors = errors;
    }
}
