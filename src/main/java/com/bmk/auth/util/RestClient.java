package com.bmk.auth.util;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import lombok.extern.log4j.Log4j2;

@Log4j2
public class RestClient {
    public static final String ACCOUNT_SID = System.getenv("twilioSid");
    public static final String AUTH_TOKEN = System.getenv("twilioToken");
    public static final String TWILIO_PHONE = System.getenv("twilioPhone");

    public static void sendOtp(String phoneNumber, int otp) {
        log.info("Sending otp to " + phoneNumber);
        Twilio.init(ACCOUNT_SID, AUTH_TOKEN);

        Message message = Message
                .creator(new PhoneNumber(phoneNumber), // to
                        new PhoneNumber(TWILIO_PHONE), // from
                        "Welcome to BookMyKainchi! " + otp + " is your OTP for registering your account. Kindly do not share this OTP with anyone")
                .create();

        log.info(message.getSid());
    }

}
