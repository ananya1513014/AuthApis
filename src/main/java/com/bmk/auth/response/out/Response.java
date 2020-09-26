package com.bmk.auth.response.out;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.HashMap;

@Data
@AllArgsConstructor
public class Response {
    String responseCode;
    Object message;
}
