package com.bmk.auth.util;

import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Log4j2
@Service
public class Scheduler {

    private static RestClient restClient;

    @Autowired
    public Scheduler(RestClient restClient){
        this.restClient = restClient;
    }

    public void pingServers(){
        Runnable runnable = new Runnable() {
            @Override
            public void run() {
                log.info("Checking servers");
                restClient.keepServersAwake();
                log.info("Server Check end");
            }
        };
        ScheduledExecutorService service = Executors.newSingleThreadScheduledExecutor();
        service.scheduleAtFixedRate(runnable, 0, 20, TimeUnit.MINUTES);
    }
}