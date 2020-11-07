package com.bmk.auth.response.out;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class ErrorResponse {
    String responseCode;
    String message;
    List<InvalidFieldResponse> errors;
}
