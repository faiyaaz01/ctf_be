package com.ctf.platform.controller.tools;

import com.ctf.platform.service.tools.CryptoEngineService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/tools/crypto")
@RequiredArgsConstructor
public class CryptoToolController {

    private final CryptoEngineService cryptoEngineService;

    @PostMapping("/decode")
    public ResponseEntity<List<Map<String, String>>> decodeMulti(@RequestBody Map<String, String> body) {
        String input = body.getOrDefault("input", "");
        return ResponseEntity.ok(cryptoEngineService.decodeMulti(input));
    }

    @PostMapping("/xor")
    public ResponseEntity<Map<String, Object>> crackXor(@RequestBody Map<String, String> body) {
        String input = body.getOrDefault("input", "");
        String inputType = body.getOrDefault("inputType", "hex");
        String mode = body.getOrDefault("mode", "single");
        String key = body.getOrDefault("key", "");
        return ResponseEntity.ok(cryptoEngineService.crackXor(input, inputType, mode, key));
    }

    @PostMapping("/hashes")
    public ResponseEntity<Map<String, Object>> computeHashes(@RequestBody Map<String, String> body) {
        String input = body.getOrDefault("input", "");
        return ResponseEntity.ok(cryptoEngineService.computeHashes(input));
    }

    @PostMapping("/encoding")
    public ResponseEntity<Map<String, Object>> processEncoding(@RequestBody Map<String, String> body) {
        String input = body.getOrDefault("input", "");
        String algorithm = body.getOrDefault("algorithm", "base64");
        String mode = body.getOrDefault("mode", "encode");
        return ResponseEntity.ok(cryptoEngineService.processEncoding(input, algorithm, mode));
    }
}
