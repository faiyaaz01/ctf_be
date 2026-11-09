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
        Map<String, Object> forged = service.forgeJwt(
                "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
                "{\"sub\":\"1337\",\"username\":\"admin\"}",
                "HS256",
                "secret"
        );
        String token = (String) forged.get("token");
        assertNotNull(token);

        Map<String, Object> analysis = service.analyzeJwt(token, "secret");
        assertTrue((Boolean) analysis.get("signatureVerified"));

        Map<String, Object> crackResult = service.crackJwtSecret(token, List.of("supersecret", "customkey"));
        assertTrue((Boolean) crackResult.get("found"));
        assertEquals("secret", crackResult.get("secret"));
    }

    @Test
    void testPayloadCatalogAndEncoding() {
        // Test category filter for SQLi
        Map<String, Object> sqliRes = service.getPayloadCatalog("sqli", null);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> sqliList = (List<Map<String, Object>>) sqliRes.get("payloads");
        assertFalse(sqliList.isEmpty());
        assertTrue(sqliList.stream().allMatch(p -> "sqli".equals(p.get("category"))));

        // Test search filter
        Map<String, Object> searchRes = service.getPayloadCatalog("all", "passwd");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> searchList = (List<Map<String, Object>>) searchRes.get("payloads");
        assertFalse(searchList.isEmpty());

        // Test encoding with parameter replacements
        Map<String, Object> encRes = service.encodePayload(
                "; {{CMD}} ;",
                "url",
                Map.of("cmd", "cat /flag.txt")
        );
        assertEquals("; cat /flag.txt ;", encRes.get("raw"));
        assertEquals("%3B+cat+%2Fflag.txt+%3B", encRes.get("encoded"));
    }
}
