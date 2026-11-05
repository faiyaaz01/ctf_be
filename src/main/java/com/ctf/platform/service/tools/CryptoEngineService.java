package com.ctf.platform.service.tools;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
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

    // ETAOIN SHRDLU English character frequency weights for scoring
    private static final Map<Character, Double> ENGLISH_FREQ = new HashMap<>();
    static {
        ENGLISH_FREQ.put('e', 12.7); ENGLISH_FREQ.put('t', 9.1); ENGLISH_FREQ.put('a', 8.2);
        ENGLISH_FREQ.put('o', 7.5);  ENGLISH_FREQ.put('i', 7.0); ENGLISH_FREQ.put('n', 6.7);
        ENGLISH_FREQ.put('s', 6.3);  ENGLISH_FREQ.put('h', 6.1); ENGLISH_FREQ.put('r', 6.0);
        ENGLISH_FREQ.put('d', 4.3);  ENGLISH_FREQ.put('l', 4.0); ENGLISH_FREQ.put('c', 2.8);
        ENGLISH_FREQ.put('u', 2.8);  ENGLISH_FREQ.put('m', 2.4); ENGLISH_FREQ.put('w', 2.4);
        ENGLISH_FREQ.put('f', 2.2);  ENGLISH_FREQ.put('g', 2.0); ENGLISH_FREQ.put('y', 2.0);
        ENGLISH_FREQ.put('p', 1.9);  ENGLISH_FREQ.put('b', 1.5); ENGLISH_FREQ.put('v', 1.0);
        ENGLISH_FREQ.put('k', 0.8);  ENGLISH_FREQ.put('j', 0.15); ENGLISH_FREQ.put('x', 0.15);
        ENGLISH_FREQ.put('q', 0.10); ENGLISH_FREQ.put('z', 0.07); ENGLISH_FREQ.put(' ', 15.0);
    }

    // ── 1. MULTI DECODER (SERVER-SIDE) ──────────────────────────────────────────
    public List<Map<String, String>> decodeMulti(String input) {
        List<Map<String, String>> results = new ArrayList<>();
        if (input == null || input.trim().isEmpty()) return results;

        String raw = input.trim();

        // 1. Base64
        try {
            byte[] decoded = Base64.getDecoder().decode(raw);
            String str = new String(decoded, StandardCharsets.UTF_8);
            if (isPrintable(str)) {
                results.add(Map.of("name", "Base64", "val", str));
            }
        } catch (Exception ignored) {}

        // 2. Hex to ASCII
        try {
            String cleanHex = raw.replaceAll("[\\s0x]+", "");
            if (cleanHex.matches("^[0-9a-fA-F]+$") && cleanHex.length() % 2 == 0) {
                byte[] bytes = new byte[cleanHex.length() / 2];
                for (int i = 0; i < cleanHex.length(); i += 2) {
                    bytes[i / 2] = (byte) Integer.parseInt(cleanHex.substring(i, i + 2), 16);
                }
                String str = new String(bytes, StandardCharsets.UTF_8);
                if (isPrintable(str)) {
                    results.add(Map.of("name", "Hex -> ASCII", "val", str));
                }
            }
        } catch (Exception ignored) {}

        // 3. URL Decode
        try {
            String urlDec = URLDecoder.decode(raw, StandardCharsets.UTF_8);
            if (!urlDec.equals(raw)) {
                results.add(Map.of("name", "URL Decoded", "val", urlDec));
            }
        } catch (Exception ignored) {}

        // 4. Binary (7/8-bit ASCII)
        try {
            String[] tokens = raw.split("[\\s,]+");
            boolean allBinary = tokens.length > 0 && Arrays.stream(tokens).allMatch(t -> t.matches("^[01]{7,8}$"));
            if (allBinary) {
                StringBuilder sb = new StringBuilder();
                for (String t : tokens) {
                    sb.append((char) Integer.parseInt(t, 2));
                }
                results.add(Map.of("name", "Binary (8-bit)", "val", sb.toString()));
            }
        } catch (Exception ignored) {}

        // 5. ROT13
        try {
            StringBuilder sb = new StringBuilder();
            for (char c : raw.toCharArray()) {
                if (c >= 'a' && c <= 'z') sb.append((char) ('a' + (c - 'a' + 13) % 26));
                else if (c >= 'A' && c <= 'Z') sb.append((char) ('A' + (c - 'A' + 13) % 26));
                else sb.append(c);
            }
            results.add(Map.of("name", "ROT13", "val", sb.toString()));
        } catch (Exception ignored) {}

        // 6. Atbash (Alphabet Reverse)
        try {
            StringBuilder sb = new StringBuilder();
            for (char c : raw.toCharArray()) {
                if (c >= 'a' && c <= 'z') sb.append((char) ('z' - (c - 'a')));
                else if (c >= 'A' && c <= 'Z') sb.append((char) ('Z' - (c - 'A')));
                else sb.append(c);
            }
            results.add(Map.of("name", "Atbash Cipher", "val", sb.toString()));
        } catch (Exception ignored) {}

        // 7. Reversed Text
        results.add(Map.of("name", "Reversed Text", "val", new StringBuilder(raw).reverse().toString()));

        return results;
    }

    // ── 2. XOR ENGINE (SINGLE-BYTE BRUTE FORCE & REPEATING KEY) ─────────────────
    public Map<String, Object> crackXor(String input, String inputType, String mode, String key) {
        Map<String, Object> resp = new HashMap<>();
        byte[] bytes;

        try {
            if ("hex".equalsIgnoreCase(inputType)) {
                String clean = input.replaceAll("[\\s0x]+", "");
                bytes = new byte[clean.length() / 2];
                for (int i = 0; i < clean.length(); i += 2) {
                    bytes[i / 2] = (byte) Integer.parseInt(clean.substring(i, i + 2), 16);
                }
            } else {
                bytes = input.getBytes(StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            resp.put("error", "Invalid input format: " + e.getMessage());
            return resp;
        }

        if ("repeating".equalsIgnoreCase(mode)) {
            if (key == null || key.isEmpty()) {
                resp.put("result", "");
                return resp;
            }
            byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
            byte[] out = new byte[bytes.length];
            for (int i = 0; i < bytes.length; i++) {
                out[i] = (byte) (bytes[i] ^ keyBytes[i % keyBytes.length]);
            }
            resp.put("result", new String(out, StandardCharsets.UTF_8));
            return resp;
        }

        // Single-byte Brute Force (0 to 255) scored in Java
        List<Map<String, Object>> candidates = new ArrayList<>();
        for (int k = 0; k < 256; k++) {
            byte[] decryptedBytes = new byte[bytes.length];
            boolean isPrintable = true;
            for (int i = 0; i < bytes.length; i++) {
                int b = (bytes[i] & 0xFF) ^ k;
                if ((b < 32 || b > 126) && b != 10 && b != 13 && b != 9) {
                    isPrintable = false;
                }
                decryptedBytes[i] = (byte) b;
            }

            if (isPrintable) {
                String text = new String(decryptedBytes, StandardCharsets.UTF_8);
                double score = scoreEnglish(text);
                Map<String, Object> candidate = new HashMap<>();
                candidate.put("key", k);
                candidate.put("keyHex", String.format("0x%02X", k));
                candidate.put("text", text);
                candidate.put("score", Math.round(score));
                candidates.add(candidate);
            }
        }

        candidates.sort((a, b) -> Long.compare((long) b.get("score"), (long) a.get("score")));
        resp.put("candidates", candidates.subList(0, Math.min(candidates.size(), 20)));
        return resp;
    }

    private double scoreEnglish(String text) {
        double score = 0;
        for (char c : text.toLowerCase().toCharArray()) {
            score += ENGLISH_FREQ.getOrDefault(c, -5.0);
        }
        return score;
    }

    // ── 3. HASH GENERATION & IDENTIFICATION (MD5, SHA1, SHA256, SHA512, NTLM) ──
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
        result.put("identification", identifyHashType(input.trim()));

        return result;
    }

    private String hashBytes(String algorithm, byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            return bytesToHex(md.digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            return "Error: " + e.getMessage();
        }
    }

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
            } else if (len == 40) {
                types.add(Map.of("name", "SHA-1", "hashcat", "-m 100", "john", "raw-sha1"));
            } else if (len == 64) {
                types.add(Map.of("name", "SHA-256", "hashcat", "-m 1400", "john", "raw-sha256"));
            } else if (len == 128) {
                types.add(Map.of("name", "SHA-512", "hashcat", "-m 1700", "john", "raw-sha512"));
            }
        }
        return types;
    }

    // ── 4. ENCODING LAB (BASE32, BASE58, BASE64, BASE85, HEX) ─────────────────
    public Map<String, Object> processEncoding(String input, String algorithm, String mode) {
        Map<String, Object> resp = new HashMap<>();
        if (input == null || input.isEmpty()) {
            resp.put("output", "");
            return resp;
        }

        try {
            boolean isEncode = "encode".equalsIgnoreCase(mode);
            String result;

            switch (algorithm.toLowerCase()) {
                case "base64":
                    if (isEncode) {
                        result = Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
                    } else {
                        result = new String(Base64.getDecoder().decode(input.trim()), StandardCharsets.UTF_8);
                    }
                    break;

                case "hex":
                    if (isEncode) {
                        result = bytesToHex(input.getBytes(StandardCharsets.UTF_8));
                    } else {
                        String clean = input.replaceAll("[\\s0x]+", "");
                        byte[] b = new byte[clean.length() / 2];
                        for (int i = 0; i < clean.length(); i += 2) {
                            b[i / 2] = (byte) Integer.parseInt(clean.substring(i, i + 2), 16);
                        }
                        result = new String(b, StandardCharsets.UTF_8);
                    }
                    break;

                case "base32":
                    result = isEncode ? encodeBase32(input.getBytes(StandardCharsets.UTF_8)) : decodeBase32(input.trim());
                    break;

                case "base58":
                    result = isEncode ? encodeBase58(input.getBytes(StandardCharsets.UTF_8)) : new String(decodeBase58(input.trim()), StandardCharsets.UTF_8);
                    break;

                case "base85":
                case "ascii85":
                    result = isEncode ? encodeAscii85(input.getBytes(StandardCharsets.UTF_8)) : new String(decodeAscii85(input.trim()), StandardCharsets.UTF_8);
                    break;

                default:
                    resp.put("error", "Unsupported encoding algorithm: " + algorithm);
                    return resp;
            }

            resp.put("output", result);
        } catch (Exception e) {
            resp.put("error", "Encoding/Decoding failed: " + e.getMessage());
        }

        return resp;
    }

    // Base32 (RFC 4648)
    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private String encodeBase32(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int val = 0, valBits = 0;
        for (byte b : data) {
            val = (val << 8) | (b & 0xFF);
            valBits += 8;
            while (valBits >= 5) {
                sb.append(BASE32_CHARS.charAt((val >> (valBits - 5)) & 31));
                valBits -= 5;
            }
        }
        if (valBits > 0) {
            sb.append(BASE32_CHARS.charAt((val << (5 - valBits)) & 31));
        }
        while (sb.length() % 8 != 0) sb.append('=');
        return sb.toString();
    }

    private String decodeBase32(String data) {
        String clean = data.replaceAll("=", "").toUpperCase();
        List<Byte> bytes = new ArrayList<>();
        int val = 0, valBits = 0;
        for (char c : clean.toCharArray()) {
            int idx = BASE32_CHARS.indexOf(c);
            if (idx == -1) continue;
            val = (val << 5) | idx;
            valBits += 5;
            if (valBits >= 8) {
                bytes.add((byte) ((val >> (valBits - 8)) & 0xFF));
                valBits -= 8;
            }
        }
        byte[] arr = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) arr[i] = bytes.get(i);
        return new String(arr, StandardCharsets.UTF_8);
    }

    // Base58 (Bitcoin Alphabet)
    private static final String BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private String encodeBase58(byte[] input) {
        if (input.length == 0) return "";
        java.math.BigInteger intData = new java.math.BigInteger(1, input);
        StringBuilder sb = new StringBuilder();
        java.math.BigInteger radix = java.math.BigInteger.valueOf(58);
        while (intData.compareTo(java.math.BigInteger.ZERO) > 0) {
            java.math.BigInteger[] divRem = intData.divideAndRemainder(radix);
            sb.append(BASE58_ALPHABET.charAt(divRem[1].intValue()));
            intData = divRem[0];
        }
        for (byte b : input) {
            if (b == 0) sb.append(BASE58_ALPHABET.charAt(0));
            else break;
        }
        return sb.reverse().toString();
    }

    private byte[] decodeBase58(String input) {
        java.math.BigInteger intData = java.math.BigInteger.ZERO;
        java.math.BigInteger radix = java.math.BigInteger.valueOf(58);
        for (char c : input.toCharArray()) {
            int idx = BASE58_ALPHABET.indexOf(c);
            if (idx == -1) continue;
            intData = intData.multiply(radix).add(java.math.BigInteger.valueOf(idx));
        }
        byte[] raw = intData.toByteArray();
        int zeros = 0;
        for (char c : input.toCharArray()) {
            if (c == BASE58_ALPHABET.charAt(0)) zeros++;
            else break;
        }
        int strip = (raw.length > 1 && raw[0] == 0) ? 1 : 0;
        byte[] res = new byte[zeros + (raw.length - strip)];
        System.arraycopy(raw, strip, res, zeros, raw.length - strip);
        return res;
    }

    // Ascii85 (Base85)
    private String encodeAscii85(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < data.length) {
            long tuple = 0;
            int padding = 0;
            for (int j = 0; j < 4; j++) {
                tuple <<= 8;
                if (i + j < data.length) tuple |= (data[i + j] & 0xFF);
                else padding++;
            }
            if (tuple == 0 && padding == 0) {
                sb.append('z');
            } else {
                char[] chars = new char[5];
                for (int j = 4; j >= 0; j--) {
                    chars[j] = (char) ('!' + (tuple % 85));
                    tuple /= 85;
                }
                for (int j = 0; j < 5 - padding; j++) sb.append(chars[j]);
            }
            i += 4;
        }
        return sb.toString();
    }

    private byte[] decodeAscii85(String input) {
        String clean = input.replaceAll("\\s+", "");
        List<Byte> bytes = new ArrayList<>();
        int i = 0;
        while (i < clean.length()) {
            if (clean.charAt(i) == 'z') {
                for (int j = 0; j < 4; j++) bytes.add((byte) 0);
                i++;
                continue;
            }
            long tuple = 0;
            int count = 0;
            for (int j = 0; j < 5; j++) {
                if (i + j < clean.length()) {
                    tuple = tuple * 85 + (clean.charAt(i + j) - '!');
                    count++;
                } else {
                    tuple = tuple * 85 + 84;
                }
            }
            for (int j = 0; j < count - 1; j++) {
                bytes.add((byte) ((tuple >> (24 - j * 8)) & 0xFF));
            }
            i += count;
        }
        byte[] res = new byte[bytes.size()];
        for (int k = 0; k < bytes.size(); k++) res[k] = bytes.get(k);
        return res;
    }

    private boolean isPrintable(String s) {
        for (char c : s.toCharArray()) {
            if ((c < 32 || c > 126) && c != '\n' && c != '\r' && c != '\t') return false;
        }
        return true;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
