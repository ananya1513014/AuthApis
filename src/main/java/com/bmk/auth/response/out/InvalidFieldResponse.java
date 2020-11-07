package com.bmk.auth.response.out;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class InvalidFieldResponse {
    String field;
    String message;
}
