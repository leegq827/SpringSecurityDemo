package com.example.SpringSecurityDemo;

import java.util.UUID;

public class JwtTokenUtil {

    public static String generateToken(String username) {
        return UUID.randomUUID().toString();
    }
}
