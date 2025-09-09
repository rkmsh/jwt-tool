package io.github.rkmsh.jwt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Minimal JWT utility with HMAC (HS256) and RSA (RS256) support.
 *
 */
public final class JwtTool {

    private JwtTool() {}

    // ---------------- Base64 URL helpers ----------------
    private static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }


    private static byte[] base64UrlDecode(String str) {
        return Base64.getUrlDecoder().decode(str);
    }

    // JSON helper
    private static String toJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        Iterator<Map.Entry<String, Object>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Object> e = it.next();
            sb.append("\"").append(e.getKey()).append("\":");
            Object val = e.getValue();
            if (val instanceof Number || val instanceof Boolean) {
                sb.append(val.toString());
            } else {
                sb.append("\"").append(val.toString()).append("\"");
            }
            if (it.hasNext()) sb.append(",");
        }
        sb.append("}");
        return sb.toString();
    }

    // JSON parser
    private static Map<String, Object> parseJson(String json) {
        Map<String, Object> map = new HashMap<>();
        String body = json.trim();
        if (body.startsWith("{") && body.endsWith("}")) {
            body = body.substring(1, body.length() - 1).trim();
            if (!body.isEmpty()) {
                String[] parts = body.split(",");
                for (String p : parts) {
                    String[] kv = p.split(":", 2);
                    String key = kv[0].trim().replaceAll("^\"|\"$", "");
                    String valRaw = kv[1].trim();
                    if (valRaw.startsWith("\"")) {
                        map.put(key, valRaw.replaceAll("^\"|\"$", ""));
                    } else if ("true".equals(valRaw) || "false".equals(valRaw)) {
                        map.put(key, Boolean.valueOf(valRaw));
                    } else {
                        try {
                            map.put(key, Long.valueOf(valRaw));
                        } catch (NumberFormatException e) {
                            map.put(key, valRaw);
                        }
                    }
                }
            }
        }
        return map;
    }

    // ---------------- Signing ----------------
    private static byte[] signHmacSha256(byte[] data, byte[] secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        return mac.doFinal(data);
    }


    private static byte[] signRsaSha256(byte[] data, RSAPrivateKey key) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }


    // verification
    private static boolean verifyRsaSha256(byte[] data, byte[] signature, RSAPublicKey key) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(key);
        sig.update(data);
        return sig.verify(signature);
    }

    // Builder
    public static class Builder {
        private final Map<String, Object> header = new HashMap<>();
        private final Map<String, Object> payload = new HashMap<>();
        private byte[] hmacSecret;
        private RSAPrivateKey rsaPrivate;


        public Builder() {
            header.put("typ", "JWT");
            header.put("alg", "HS256");
        }


        public Builder withIssuer(String iss) { payload.put("iss", iss); return this; }
        public Builder withSubject(String sub) { payload.put("sub", sub); return this; }
        public Builder withAudience(String aud) { payload.put("aud", aud); return this; }
        public Builder withClaim(String name, Object value) { payload.put(name, value); return this; }
        public Builder withIssuedAt(Instant iat) { payload.put("iat", iat.getEpochSecond()); return this; }
        public Builder withExpiresAt(Instant exp) { payload.put("exp", exp.getEpochSecond()); return this; }
        public Builder withHmacSecret(byte[] secret) { this.hmacSecret = secret; header.put("alg", "HS256"); return this; }
        public Builder withRsaPrivate(RSAPrivateKey key) { this.rsaPrivate = key; header.put("alg", "RS256"); return this; }


        public String sign() throws Exception {
            String headerJson = toJson(header);
            String payloadJson = toJson(payload);
            String headerEnc = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8));
            String payloadEnc = base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8));
            String signingInput = headerEnc + "." + payloadEnc;


            byte[] signature;
            if ("HS256".equals(header.get("alg"))) {
                if (hmacSecret == null) throw new IllegalStateException("No HMAC secret");
                signature = signHmacSha256(signingInput.getBytes(StandardCharsets.UTF_8), hmacSecret);
            } else {
                if (rsaPrivate == null) throw new IllegalStateException("No RSA private key");
                signature = signRsaSha256(signingInput.getBytes(StandardCharsets.UTF_8), rsaPrivate);
            }


            return signingInput + "." + base64UrlEncode(signature);
        }
    }

    // ---------------- Verifier ----------------
    public static class Verifier {
        private byte[] hmacSecret;
        private RSAPublicKey rsaPublic;
        private String expectedIssuer;
        private String expectedAudience;
        private boolean checkExpiry = true;


        public Verifier withHmacSecret(byte[] secret) { this.hmacSecret = secret; return this; }
        public Verifier withRsaPublic(RSAPublicKey key) { this.rsaPublic = key; return this; }
        public Verifier expectIssuer(String iss) { this.expectedIssuer = iss; return this; }
        public Verifier expectAudience(String aud) { this.expectedAudience = aud; return this; }
        public Verifier checkExpiry(boolean b) { this.checkExpiry = b; return this; }


        public Map<String, Object> verify(String token) throws Exception {
            String[] parts = token.split("\\.");
            if (parts.length != 3) throw new IllegalArgumentException("Invalid token");


            String headerJson = new String(base64UrlDecode(parts[0]), StandardCharsets.UTF_8);
            String payloadJson = new String(base64UrlDecode(parts[1]), StandardCharsets.UTF_8);
            byte[] signature = base64UrlDecode(parts[2]);


            Map<String, Object> header = parseJson(headerJson);
            Map<String, Object> payload = parseJson(payloadJson);


            String alg = (String) header.get("alg");
            String signingInput = parts[0] + "." + parts[1];


            boolean valid;
            if ("HS256".equals(alg)) {
                if (hmacSecret == null) throw new IllegalStateException("No HMAC secret");
                byte[] expectedSig = signHmacSha256(signingInput.getBytes(StandardCharsets.UTF_8), hmacSecret);
                valid = MessageDigest.isEqual(expectedSig, signature);
            } else if ("RS256".equals(alg)) {
                if (rsaPublic == null) throw new IllegalStateException("No RSA public key");
                valid = verifyRsaSha256(signingInput.getBytes(StandardCharsets.UTF_8), signature, rsaPublic);
            } else {
                throw new IllegalStateException("Unsupported alg: " + alg);
            }


            if (!valid) throw new SecurityException("Signature verification failed");


            if (checkExpiry && payload.containsKey("exp")) {
                long exp = ((Number) payload.get("exp")).longValue();
                if (Instant.now().getEpochSecond() > exp) throw new SecurityException("Token expired");
            }
            if (expectedIssuer != null && !expectedIssuer.equals(payload.get("iss"))) {
                throw new SecurityException("Issuer mismatch");
            }
            if (expectedAudience != null && !expectedAudience.equals(payload.get("aud"))) {
                throw new SecurityException("Audience mismatch");
            }
            return payload;
        }
    }
}
