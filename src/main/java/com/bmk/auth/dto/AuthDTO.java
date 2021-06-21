package com.bmk.auth.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthDTO {
    String phone;
    String deviceId;
}
