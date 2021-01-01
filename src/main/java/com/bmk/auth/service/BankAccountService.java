package com.bmk.auth.service;

import com.bmk.auth.bo.BankAccount;
import com.bmk.auth.repository.BankAccountRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class BankAccountService {

    private static BankAccountRepo bankAccountRepo;

    @Autowired
    public BankAccountService(BankAccountRepo bankAccountRepo) {
        this.bankAccountRepo = bankAccountRepo;
    }


    public boolean addBankAccount(BankAccount bankAccount) {
        bankAccountRepo.save(bankAccount);
        return true;
    }

    public BankAccount getBankAccount(Long userId) {
        try {
            return bankAccountRepo.findById(userId).get();
        } catch (Exception e) {
            return null;
        }
    }
}