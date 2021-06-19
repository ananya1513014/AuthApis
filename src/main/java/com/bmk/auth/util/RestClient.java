package com.bmk.auth.util;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

@Log4j2
@Service
public class RestClient {
    public static final String ACCOUNT_SID = System.getenv("twilioSid");
    public static final String AUTH_TOKEN = System.getenv("twilioToken");
    public static final String TWILIO_PHONE = System.getenv("twilioPhone");

    private final RestTemplate restTemplate;

    @Autowired
    public RestClient(RestTemplateBuilder restTemplateBuilder) {
        this.restTemplate = restTemplateBuilder.build();
    }

    public static void sendOtp(String phoneNumber, String messageText) {
        log.info("Sending otp to " + phoneNumber);
        Twilio.init(ACCOUNT_SID, AUTH_TOKEN);

        Message message = Message
                .creator(new PhoneNumber(phoneNumber), // to
                        new PhoneNumber(TWILIO_PHONE), // from
                        messageText)
                .create();

        log.info(message.getSid());
    }

    public void keepServersAwake() {
        String baseUrl = "https://bmkbookings.herokuapp.com//booking/ping";
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>("body", headers);
        String str =  restTemplate.exchange(baseUrl, HttpMethod.GET, entity, String.class).getBody();
        log.info("Booking Server Ping:"+str);
    }

}
