package com.bmk.auth.response.out;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class DeviceIdResponse {
    String responseCode;
    String message;
    String deviceId;
}