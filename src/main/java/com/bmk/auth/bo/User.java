package com.bmk.auth.bo;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Date;

@Entity
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class User {
    @Id
    @GeneratedValue
    Long staticUserId;
    @NotNull
    String email;
    @NotNull
    @Size(min = 8, max = 24)
    String password;
    @NotNull
    String name;
    Date dateOfBirth;
    String gender;
    @NotNull
    @Size(min = 13, max = 13)
    String phone;
    String userType = "client";
    String deviceId;
}