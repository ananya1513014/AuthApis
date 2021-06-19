package com.bmk.auth;

import com.bmk.auth.util.Scheduler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class AuthApp {

	static Scheduler scheduler;

	@Autowired
	public AuthApp(Scheduler scheduler) {
		this.scheduler = scheduler;
	}

	public static void main(String[] args) {
		SpringApplication.run(AuthApp.class, args);
		scheduler.pingServers();
	}

}
