package com.bmk.auth.response.out;

import com.bmk.auth.bo.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserListResponse {
    String responseCode;
    String message;
    User[] userList;
}
