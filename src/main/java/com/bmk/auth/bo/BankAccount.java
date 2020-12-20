package com.bmk.auth.bo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.Id;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
public class BankAccount {
    @Id
    Long userId;
    String accountNumber;
    String ifscCode;
    String holderName;
}
