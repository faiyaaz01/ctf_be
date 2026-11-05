package com.ctf.platform.service.tools;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.*;

@Service
public class CryptoEngineService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // ── 1. HASH GENERATION & IDENTIFICATION (MD5, SHA1, SHA256, SHA512, NTLM) ──
    public Map<String, Object> computeHashes(String input) {
        Map<String, Object> result = new HashMap<>();
        if (input == null || input.isEmpty()) {
            result.put("error", "Input string cannot be empty");
            return result;
        }

        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);

        result.put("input", input);
        result.put("md5", hashBytes("MD5", bytes));
        result.put("sha1", hashBytes("SHA-1", bytes));
        result.put("sha256", hashBytes("SHA-256", bytes));
        result.put("sha512", hashBytes("SHA-512", bytes));
        result.put("ntlm", computeNtlm(input));

        // Identify possible hash type if input looks like a hash
        result.put("identification", identifyHashType(input.trim()));

        return result;
    }

    private String hashBytes(String algorithm, byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] digest = md.digest(bytes);
            return bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            return "Error: " + e.getMessage();
        }
    }

    // NTLM is MD4(UTF-16LE(password)) via BouncyCastle
    private String computeNtlm(String password) {
        try {
            MessageDigest md4 = MessageDigest.getInstance("MD4", "BC");
            byte[] unicodePassword = password.getBytes(StandardCharsets.UTF_16LE);
            return bytesToHex(md4.digest(unicodePassword));
        } catch (Exception e) {
            return "N/A";
        }
    }

    private List<Map<String, String>> identifyHashType(String text) {
        List<Map<String, String>> types = new ArrayList<>();
        int len = text.length();
        boolean isHex = text.matches("^[0-9a-fA-F]+$");

        if (isHex) {
            if (len == 32) {
                types.add(Map.of("name", "MD5", "hashcat", "-m 0", "john", "raw-md5"));
                types.add(Map.of("name", "NTLM", "hashcat", "-m 1000", "john", "nt"));
                types.add(Map.of("name", "MD4", "hashcat", "-m 900", "john", "raw-md4"));
            } else if (len == 40) {
                types.add(Map.of("name", "SHA-1", "hashcat", "-m 100", "john", "raw-sha1"));
                types.add(Map.of("name", "MySQL5", "hashcat", "-m 300", "john", "mysql-sha1"));
            } else if (len == 56) {
                types.add(Map.of("name", "SHA-224", "hashcat", "-m 1300", "john", "raw-sha224"));
            } else if (len == 64) {
                types.add(Map.of("name", "SHA-256", "hashcat", "-m 1400", "john", "raw-sha256"));
                types.add(Map.of("name", "Keccak-256", "hashcat", "-m 17800", "john", "keccak-256"));
            } else if (len == 96) {
                types.add(Map.of("name", "SHA-384", "hashcat", "-m 10800", "john", "raw-sha384"));
            } else if (len == 128) {
                types.add(Map.of("name", "SHA-512", "hashcat", "-m 1700", "john", "raw-sha512"));
                types.add(Map.of("name", "Whirlpool", "hashcat", "-m 6100", "john", "whirlpool"));
            }
        }

        if (text.startsWith("$2a$") || text.startsWith("$2b$") || text.startsWith("$2y$")) {
            types.add(Map.of("name", "bcrypt", "hashcat", "-m 3200", "john", "bcrypt"));
        }

        return types;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
