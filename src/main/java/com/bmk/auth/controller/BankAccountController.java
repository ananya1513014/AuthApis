package com.bmk.auth.controller;

import com.bmk.auth.bo.BankAccount;
import com.bmk.auth.exceptions.InvalidTokenException;
import com.bmk.auth.response.out.Response;
import com.bmk.auth.service.BankAccountService;
import com.bmk.auth.util.TokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping("bank")
@RestController
public class BankAccountController {

    private final BankAccountService bankAccountService;

    @Autowired
    public BankAccountController(BankAccountService bankAccountService){
        this.bankAccountService = bankAccountService;
    }

    @PostMapping
    public ResponseEntity addBankDetails(@RequestHeader String token, @RequestBody BankAccount bankAccount) throws InvalidTokenException {
        Long userId = TokenUtil.getUserId(token);
        bankAccount.setUserId(userId);
        bankAccountService.addBankAccount(bankAccount);
        return ResponseEntity.ok(new Response("200", "Success"));
    }

    @GetMapping
    public ResponseEntity getBankDetails(@RequestHeader String token) throws InvalidTokenException {
        Long userId = TokenUtil.getUserId(token);
        return ResponseEntity.ok(new Response("200", bankAccountService.getBankAccount(userId)));
    }
}
