package org.jwt.example;

import io.github.rkmsh.jwt.JwtTool;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;

public class JwtExample {
    public static void main(String[] args) throws Exception {
        byte[] secret = "supersecret1234567890".getBytes(StandardCharsets.UTF_8);
        String token = new JwtTool.Builder()
                .withIssuer("example.com")
                .withSubject("user-1")
                .withAudience("aud-1")
                .withClaim("role", "admin")
                .withIssuedAt(Instant.now())
                .withExpiresAt(Instant.now().plusSeconds(60))
                .withHmacSecret(secret)
                .sign();
        System.out.println("HMAC token: " + token);


        Map<String, Object> verified = new JwtTool.Verifier()
                .withHmacSecret(secret)
                .expectIssuer("example.com")
                .expectAudience("aud-1")
                .verify(token);
        System.out.println("Verified claims: " + verified);
    }
}
