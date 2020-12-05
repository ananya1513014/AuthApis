package com.bmk.auth.request;

import lombok.Data;

import javax.validation.constraints.NotEmpty;

@Data
public class LoginRequest {
    @NotEmpty
    String email;
    @NotEmpty
    String password;
    String deviceId;
}
