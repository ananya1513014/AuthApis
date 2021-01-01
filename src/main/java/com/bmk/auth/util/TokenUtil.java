package com.bmk.auth.util;

import com.bmk.auth.bo.User;
import com.bmk.auth.exceptions.InvalidTokenException;
import com.bmk.auth.util.Constants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.*;

public class TokenUtil {

    private final static String SECRET_KEY = System.getenv(Constants.SECRET_PARAM_KEY);
    private final static long ttlMillis = 172800000;    // 2*24*60*60*1000
    private static Map<String, List<String>> accessMap;
    static SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
    static long nowMillis = System.currentTimeMillis();
    static Date now = new Date(nowMillis);
    static byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
    static Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

    public TokenUtil(){
        accessMap = new HashMap<>();
        accessMap.put("superuser", Arrays.asList(Constants.SUPERUSER_ACCESS.split(",")));
        accessMap.put("admin", Arrays.asList(Constants.ADMIN_ACCESS.split(",")));
        accessMap.put("merchant", Arrays.asList(Constants.MERCHANT_ACCESS.split(",")));
        accessMap.put("client", Arrays.asList(Constants.CLIENT_ACCESS.split(",")));
    }

    public static String getToken(User user){

        JwtBuilder builder = Jwts.builder().setId(user.getStaticUserId().toString()).setIssuedAt(now).setSubject(user.getUserType()).setIssuer("issuwr").signWith(signatureAlgorithm, signingKey);

        if(ttlMillis > 0) {
            long expMillis = System.currentTimeMillis() + ttlMillis;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp);
        }
        return builder.compact();
    }

     public static Long authorizeApi(String token, String apiType) throws InvalidTokenException {
        System.out.println(getUserId(token)+" "+apiType+" "+accessMap.get(getUserType(token)));
        if(!accessMap.get(getUserType(token)).contains(apiType)) throw new InvalidTokenException();
        return getUserId(token);
    }

    public static Long getUserId(String jwt) throws InvalidTokenException {
        try {
            return Long.parseLong(getClaim(jwt).getId());
        } catch(Exception exp){
            throw new InvalidTokenException();
        }
    }

    public static String getUserType(String jwt) {
        try {
            return getClaim(jwt).getSubject();
        } catch(Exception exp){
            return null;
        }
    }

    public static Claims getClaim(String jwt){
        return Jwts.parser()
                .setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
                .parseClaimsJws(jwt).getBody();
    }

}