package com.bmk.auth.response.out;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LoginResponse {
    String responseCode;
    Object message;
    String token;
}
