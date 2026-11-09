package com.ctf.platform.controller.tools;

import com.ctf.platform.service.tools.WebEngineService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/tools/web")
@RequiredArgsConstructor
public class WebToolController {

    private final WebEngineService webEngineService;

    @PostMapping("/jwt/analyze")
    public ResponseEntity<Map<String, Object>> analyzeJwt(@RequestBody Map<String, String> body) {
        String token = body.getOrDefault("token", "");
        String secret = body.getOrDefault("secret", "");
        return ResponseEntity.ok(webEngineService.analyzeJwt(token, secret));
    }

    @PostMapping("/jwt/forge")
    public ResponseEntity<Map<String, Object>> forgeJwt(@RequestBody Map<String, String> body) {
        String headerJson = body.getOrDefault("headerJson", "{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payloadJson = body.getOrDefault("payloadJson", "{}");
        String alg = body.getOrDefault("algorithm", "none");
        String secret = body.getOrDefault("secret", "");
        return ResponseEntity.ok(webEngineService.forgeJwt(headerJson, payloadJson, alg, secret));
    }

    @PostMapping("/jwt/crack")
    public ResponseEntity<Map<String, Object>> crackJwt(@RequestBody Map<String, Object> body) {
        String token = (String) body.getOrDefault("token", "");
        @SuppressWarnings("unchecked")
        List<String> customWordlist = (List<String>) body.get("customWordlist");
        return ResponseEntity.ok(webEngineService.crackJwtSecret(token, customWordlist));
    }
}
