package com.bmk.auth.request;

import lombok.Data;

import java.util.Date;

@Data
public class UserBuilder {
    String email;
    String password;
    String name;
    String dateOfBirth;
    String gender;
    String phone;
}