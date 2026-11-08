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

    @PostMapping("/number")
    public ResponseEntity<Map<String, Object>> convertNumber(@RequestBody Map<String, String> body) {
        String value = body.getOrDefault("value", "0");
        String fromRadix = body.getOrDefault("fromRadix", "dec");
        return ResponseEntity.ok(cryptoEngineService.convertNumber(value, fromRadix));
    }

    @PostMapping("/rsa-helper")
    public ResponseEntity<Map<String, Object>> computeRsa(@RequestBody Map<String, String> body) {
        String p = body.getOrDefault("p", "");
        String q = body.getOrDefault("q", "");
        String e = body.getOrDefault("e", "65537");
        return ResponseEntity.ok(cryptoEngineService.computeRsa(p, q, e));
    }

    @PostMapping("/atbash")
    public ResponseEntity<Map<String, String>> atbash(@RequestBody Map<String, String> body) {
        String text = body.getOrDefault("text", "");
        return ResponseEntity.ok(cryptoEngineService.atbash(text));
    }

    @PostMapping("/railfence")
    public ResponseEntity<Map<String, String>> railFence(@RequestBody Map<String, String> body) {
        String text = body.getOrDefault("text", "");
        int rails = 3;
        try {
            rails = Integer.parseInt(body.getOrDefault("rails", "3"));
        } catch (NumberFormatException ignored) {}
        String mode = body.getOrDefault("mode", "decrypt");
        return ResponseEntity.ok(cryptoEngineService.railFence(text, rails, mode));
    }

    @PostMapping("/baconian")
    public ResponseEntity<Map<String, String>> baconian(@RequestBody Map<String, String> body) {
        String text = body.getOrDefault("text", "");
        String mode = body.getOrDefault("mode", "decrypt");
        return ResponseEntity.ok(cryptoEngineService.baconian(text, mode));
    }

    @PostMapping("/bitwise")
    public ResponseEntity<Map<String, Object>> bitwiseCalc(@RequestBody Map<String, String> body) {
        String a = body.getOrDefault("a", "0");
        String b = body.getOrDefault("b", "0");
        String op = body.getOrDefault("op", "AND");
        int bits = 32;
        try {
            bits = Integer.parseInt(body.getOrDefault("bits", "32"));
        } catch (NumberFormatException ignored) {}
        return ResponseEntity.ok(cryptoEngineService.bitwiseCalc(a, b, op, bits));
    }

    @PostMapping("/rsa-wiener")
    public ResponseEntity<Map<String, Object>> rsaWiener(@RequestBody Map<String, String> body) {
        String n = body.getOrDefault("n", "");
        String e = body.getOrDefault("e", "");
        return ResponseEntity.ok(cryptoEngineService.rsaWienerAttack(n, e));
    }

    @PostMapping("/rsa-fermat")
    public ResponseEntity<Map<String, Object>> rsaFermat(@RequestBody Map<String, String> body) {
        String n = body.getOrDefault("n", "");
        return ResponseEntity.ok(cryptoEngineService.rsaFermatFactor(n));
    }

    @PostMapping("/vigenere")
    public ResponseEntity<Map<String, Object>> solveVigenere(@RequestBody Map<String, String> body) {
        String text = body.getOrDefault("text", "");
        String key = body.getOrDefault("key", "");
        return ResponseEntity.ok(cryptoEngineService.solveVigenere(text, key));
    }

    @PostMapping("/padding-oracle")
    public ResponseEntity<Map<String, Object>> simulatePaddingOracle(@RequestBody Map<String, String> body) {
        String cipherHex = body.getOrDefault("cipherHex", "");
        int blockIndex = 0;
        try {
            blockIndex = Integer.parseInt(body.getOrDefault("blockIndex", "0"));
        } catch (NumberFormatException ignored) {}
        return ResponseEntity.ok(cryptoEngineService.simulatePaddingOracle(cipherHex, blockIndex));
    }

    @PostMapping("/substitution")
    public ResponseEntity<Map<String, Object>> substitutionSolver(@RequestBody Map<String, String> body) {
        String text = body.getOrDefault("text", "");
        String keyMap = body.getOrDefault("keyMap", "");
        return ResponseEntity.ok(cryptoEngineService.substitutionSolver(text, keyMap));
    }

    @PostMapping("/discrete-log")
    public ResponseEntity<Map<String, Object>> discreteLog(@RequestBody Map<String, String> body) {
        String g = body.getOrDefault("g", "");
        String h = body.getOrDefault("h", "");
        String p = body.getOrDefault("p", "");
        return ResponseEntity.ok(cryptoEngineService.discreteLog(g, h, p));
    }

    @PostMapping("/crib-drag")
    public ResponseEntity<Map<String, Object>> cribDrag(@RequestBody Map<String, String> body) {
        String cipher1 = body.getOrDefault("cipher1", "");
        String cipher2 = body.getOrDefault("cipher2", "");
        String crib = body.getOrDefault("crib", "");
        return ResponseEntity.ok(cryptoEngineService.cribDrag(cipher1, cipher2, crib));
    }

    @PostMapping("/rot-table")
    public ResponseEntity<Map<String, Object>> rotTable(@RequestBody Map<String, String> body) {
        String text = body.getOrDefault("text", "");
        return ResponseEntity.ok(cryptoEngineService.rotShiftTable(text));
    }
}
