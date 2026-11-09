package com.ctf.platform.controller.tools;

import com.ctf.platform.service.tools.NetworkEngineService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/tools/network")
@RequiredArgsConstructor
public class NetworkToolController {

    private final NetworkEngineService networkEngineService;

    @PostMapping("/calc")
    public ResponseEntity<Map<String, Object>> calculateSubnet(@RequestBody Map<String, Object> body) {
        String ip = (String) body.getOrDefault("ip", "");
        Integer cidr = null;
        if (body.containsKey("cidr") && body.get("cidr") != null) {
            try {
                cidr = Integer.parseInt(body.get("cidr").toString());
            } catch (NumberFormatException ignored) {}
        }
        return ResponseEntity.ok(networkEngineService.calculateSubnet(ip, cidr));
    }

    @PostMapping("/osint")
    public ResponseEntity<Map<String, Object>> generateOsintQueries(@RequestBody Map<String, Object> body) {
        String target = (String) body.getOrDefault("target", "");
        String type = (String) body.getOrDefault("type", "auto");
        boolean queryCrtSh = Boolean.TRUE.equals(body.get("queryCrtSh"));
        return ResponseEntity.ok(networkEngineService.generateOsintQueries(target, type, queryCrtSh));
    }

    @PostMapping("/osint/subdomains")
    public ResponseEntity<Map<String, Object>> fetchSubdomains(@RequestBody Map<String, String> body) {
        String domain = body.getOrDefault("domain", "");
        return ResponseEntity.ok(Map.of(
                "domain", domain,
                "subdomains", networkEngineService.fetchCrtShSubdomains(domain)
        ));
    }

    @GetMapping("/wordlists")
    public ResponseEntity<Map<String, Object>> getWordlists(
            @RequestParam(required = false, defaultValue = "all") String category,
            @RequestParam(required = false) String query) {
        return ResponseEntity.ok(networkEngineService.getWordlistsCatalog(category, query));
    }

    @PostMapping("/wordlists/commands")
    public ResponseEntity<Map<String, Object>> generateCommands(@RequestBody Map<String, String> body) {
        String wordlistId = body.getOrDefault("wordlistId", "rockyou");
        String target = body.getOrDefault("target", "http://target.htb");
        return ResponseEntity.ok(networkEngineService.generateWordlistCommands(wordlistId, target));
    }
}
