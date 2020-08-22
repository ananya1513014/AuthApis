package com.bmk.auth.bo;

import com.bmk.auth.request.UserBuilder;
import com.bmk.auth.util.Security;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

@Entity
@Data
@NoArgsConstructor
public class User {
    @Id
    @GeneratedValue
    Long staticUserId;
    String email;
    String password;
    String name;
    Date dateOfBirth;
    String gender;
    String phone;

    public User(UserBuilder user){
        this.email = user.getEmail();
        this.password = Security.encrypt(user.getPassword(), "sec");
        this.name = user.getName();
        try {
            this.dateOfBirth = new SimpleDateFormat("dd/MM/yyyy").parse(user.getDateOfBirth());
        } catch (ParseException e) {
            this.dateOfBirth = null;
        }
        this.gender = user.getGender();
        this.phone = user.getPhone();
    }
}