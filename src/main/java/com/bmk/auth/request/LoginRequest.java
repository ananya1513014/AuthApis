package com.bmk.auth.request;

import lombok.Data;

@Data
public class LoginRequest {
    String email;
    String password;
    String deviceId;
}
