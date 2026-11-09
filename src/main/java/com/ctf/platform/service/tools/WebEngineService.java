package com.ctf.platform.service.tools;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class WebEngineService {

    private final ObjectMapper objectMapper;

    private static final List<String> DEFAULT_WORDLIST = List.of(
            "secret", "jwt", "password", "123456", "admin", "secret123", "key",
            "supersecret", "qwerty", "token", "root", "test", "development",
            "production", "flag", "ctf", "letmein", "changeme", "default",
            "master", "pass", "12345678", "welcome", "auth", "api"
    );

    public Map<String, Object> analyzeJwt(String token, String secret) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (token == null || token.trim().isEmpty()) {
            result.put("error", "JWT token string cannot be empty");
            return result;
        }

        String clean = token.trim();
        String[] parts = clean.split("\\.", -1);
        if (parts.length < 2 || parts.length > 3) {
            result.put("error", "Invalid JWT format. Expected 2 or 3 dot-separated segments.");
            return result;
        }

        try {
            // Decode Header & Payload
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            String signatureB64 = parts.length == 3 ? parts[2] : "";

            Map<String, Object> headerMap = objectMapper.readValue(headerJson, new TypeReference<>() {});
            Map<String, Object> payloadMap = objectMapper.readValue(payloadJson, new TypeReference<>() {});

            result.put("header", headerMap);
            result.put("payload", payloadMap);
            result.put("headerJson", objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(headerMap));
            result.put("payloadJson", objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(payloadMap));
            result.put("signatureRaw", signatureB64);

            String alg = String.valueOf(headerMap.getOrDefault("alg", "none"));
            result.put("algorithm", alg);

            // Audit Findings
            List<Map<String, String>> findings = new ArrayList<>();
            if ("none".equalsIgnoreCase(alg)) {
                findings.add(Map.of("level", "CRITICAL", "title", "Algorithm 'none' Detected",
                        "desc", "Token signature validation is completely disabled. Anyone can forge arbitrary claims."));
            } else if (alg.startsWith("HS")) {
                findings.add(Map.of("level", "INFO", "title", "HMAC Symmetric Signing (" + alg + ")",
                        "desc", "Shared secret used for both signing and verification. Vulnerable if secret is weak or bruteforceable."));
            } else if (alg.startsWith("RS")) {
                findings.add(Map.of("level", "INFO", "title", "RSA Asymmetric Signing (" + alg + ")",
                        "desc", "Private key signs, public key verifies. Check for Key Confusion (CVE-2016-5431: RS256 -> HS256)."));
            }

            // Expiration validation
            if (payloadMap.containsKey("exp")) {
                try {
                    long exp = Long.parseLong(String.valueOf(payloadMap.get("exp")));
                    Instant expInstant = Instant.ofEpochSecond(exp);
                    boolean isExpired = Instant.now().isAfter(expInstant);
                    result.put("expTimestamp", exp);
                    result.put("expIso", expInstant.toString());
                    result.put("isExpired", isExpired);
                    if (isExpired) {
                        findings.add(Map.of("level", "WARNING", "title", "Token Has Expired",
                                "desc", "Expired at " + expInstant.toString()));
                    }
                } catch (Exception ignored) {}
            } else {
                findings.add(Map.of("level", "WARNING", "title", "No Expiration ('exp') Claim",
                        "desc", "Token will remain valid indefinitely unless revoked server-side."));
            }

            result.put("findings", findings);

            // Signature verification if secret provided
            if (secret != null && !secret.trim().isEmpty() && alg.startsWith("HS")) {
                boolean verified = verifyHmac(parts[0], parts[1], signatureB64, alg, secret);
                result.put("signatureVerified", verified);
            } else if ("none".equalsIgnoreCase(alg)) {
                result.put("signatureVerified", signatureB64.isEmpty());
            }

        } catch (Exception e) {
            result.put("error", "Failed to parse JWT: " + e.getMessage());
        }

        return result;
    }

    public Map<String, Object> forgeJwt(String headerJson, String payloadJson, String alg, String secret) {
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            Map<String, Object> headerMap = objectMapper.readValue(headerJson, new TypeReference<>() {});
            Map<String, Object> payloadMap = objectMapper.readValue(payloadJson, new TypeReference<>() {});

            headerMap.put("alg", alg);
            if (!headerMap.containsKey("typ")) {
                headerMap.put("typ", "JWT");
            }

            String hB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(objectMapper.writeValueAsBytes(headerMap));
            String pB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(objectMapper.writeValueAsBytes(payloadMap));

            String token;
            if ("none".equalsIgnoreCase(alg)) {
                token = hB64 + "." + pB64 + ".";
            } else if (alg.startsWith("HS")) {
                if (secret == null) secret = "";
                String sig = signHmac(hB64 + "." + pB64, alg, secret);
                token = hB64 + "." + pB64 + "." + sig;
            } else {
                result.put("error", "Unsupported algorithm for direct signing: " + alg + ". Supported: none, HS256, HS384, HS512.");
                return result;
            }

            result.put("token", token);
            result.put("headerJson", objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(headerMap));
            result.put("payloadJson", objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(payloadMap));
            result.put("algorithm", alg);
        } catch (Exception e) {
            result.put("error", "Failed to forge JWT: " + e.getMessage());
        }
        return result;
    }

    public Map<String, Object> crackJwtSecret(String token, List<String> customList) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (token == null || !token.contains(".")) {
            result.put("error", "Invalid JWT format");
            return result;
        }

        String[] parts = token.trim().split("\\.", -1);
        if (parts.length != 3 || parts[2].isEmpty()) {
            result.put("error", "Token has no signature to crack");
            return result;
        }

        try {
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            Map<String, Object> headerMap = objectMapper.readValue(headerJson, new TypeReference<>() {});
            String alg = String.valueOf(headerMap.getOrDefault("alg", "HS256"));

            if (!alg.startsWith("HS")) {
                result.put("error", "Dictionary attack only supported for HMAC (HS256/384/512). Token alg is " + alg);
                return result;
            }

            Set<String> wordlist = new LinkedHashSet<>(DEFAULT_WORDLIST);
            if (customList != null) {
                wordlist.addAll(customList);
            }

            int attempts = 0;
            String signingInput = parts[0] + "." + parts[1];
            String expectedSig = parts[2];

            for (String candidate : wordlist) {
                attempts++;
                String candidateSig = signHmac(signingInput, alg, candidate);
                if (expectedSig.equals(candidateSig)) {
                    result.put("found", true);
                    result.put("secret", candidate);
                    result.put("algorithm", alg);
                    result.put("attempts", attempts);
                    return result;
                }
            }

            result.put("found", false);
            result.put("attempts", attempts);
            result.put("message", "Secret not found in the tested " + attempts + " candidate words.");
        } catch (Exception e) {
            result.put("error", "Crack error: " + e.getMessage());
        }
        return result;
    }

    private boolean verifyHmac(String headerB64, String payloadB64, String signatureB64, String alg, String secret) {
        try {
            String expected = signHmac(headerB64 + "." + payloadB64, alg, secret);
            return expected.equals(signatureB64);
        } catch (Exception e) {
            return false;
        }
    }

    private String signHmac(String data, String alg, String secret) throws Exception {
        String hmacAlg = switch (alg.toUpperCase()) {
            case "HS384" -> "HmacSHA384";
            case "HS512" -> "HmacSHA512";
            default -> "HmacSHA256";
        };

        Mac mac = Mac.getInstance(hmacAlg);
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), hmacAlg);
        mac.init(keySpec);
        byte[] sigBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes);
    }
}
