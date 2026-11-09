package com.ctf.platform;

import com.ctf.platform.service.tools.WebEngineService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class WebEngineServiceTest {

    private final WebEngineService service = new WebEngineService(new ObjectMapper());

    @Test
    void testForgeAndAnalyzeNoneAlg() {
        // 1. Forge a token with alg: none
        Map<String, Object> forged = service.forgeJwt(
                "{\"alg\":\"none\",\"typ\":\"JWT\"}",
                "{\"user\":\"guest\",\"role\":\"admin\",\"flag\":\"ctf{fake_flag}\"}",
                "none",
                ""
        );
        assertNull(forged.get("error"));
        String token = (String) forged.get("token");
        assertNotNull(token);
        assertTrue(token.endsWith("."));

        // 2. Analyze the token
        Map<String, Object> analysis = service.analyzeJwt(token, "");
        assertNull(analysis.get("error"));
        assertEquals("none", analysis.get("algorithm"));
        assertTrue((Boolean) analysis.get("signatureVerified"));

        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) analysis.get("payload");
        assertEquals("admin", payload.get("role"));
    }

    @Test
    void testForgeAndCrackHmacSecret() {
        // 1. Forge with secret "secret"
        Map<String, Object> forged = service.forgeJwt(
                "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
                "{\"sub\":\"1337\",\"username\":\"admin\"}",
                "HS256",
                "secret"
        );
        String token = (String) forged.get("token");
        assertNotNull(token);

        // 2. Verify with correct secret
        Map<String, Object> analysis = service.analyzeJwt(token, "secret");
        assertTrue((Boolean) analysis.get("signatureVerified"));

        // 3. Crack with dictionary
        Map<String, Object> crackResult = service.crackJwtSecret(token, List.of("supersecret", "customkey"));
        assertTrue((Boolean) crackResult.get("found"));
        assertEquals("secret", crackResult.get("secret"));
    }
}
