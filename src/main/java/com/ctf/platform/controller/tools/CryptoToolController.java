package com.ctf.platform.controller.tools;

import com.ctf.platform.service.tools.CryptoEngineService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/tools/crypto")
@RequiredArgsConstructor
public class CryptoToolController {

    private final CryptoEngineService cryptoEngineService;

    @PostMapping("/hashes")
    public ResponseEntity<Map<String, Object>> computeHashes(@RequestBody Map<String, String> body) {
        String input = body.getOrDefault("input", "");
        return ResponseEntity.ok(cryptoEngineService.computeHashes(input));
    }
}
