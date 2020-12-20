package com.bmk.auth.repository;

import com.bmk.auth.bo.BankAccount;
import org.springframework.data.repository.CrudRepository;

public interface BankAccountRepo extends CrudRepository<BankAccount, Long> {
}
