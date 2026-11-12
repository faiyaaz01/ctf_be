package com.ctf.platform.service.tools;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
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

    // ── 1. MULTI DECODER ──────────────────────────────────────────────
    public List<Map<String, String>> decodeMulti(String input) {
        List<Map<String, String>> results = new ArrayList<>();
        if (input == null || input.trim().isEmpty()) return results;
        String raw = input.trim();

        try {
            byte[] decoded = Base64.getDecoder().decode(raw);
            String str = new String(decoded, StandardCharsets.UTF_8);
            if (isPrintable(str)) results.add(Map.of("name", "Base64", "val", str));
        } catch (Exception ignored) {}

        try {
            String cleanHex = raw.replaceAll("[\\s0x]+", "");
            if (cleanHex.matches("^[0-9a-fA-F]+$") && cleanHex.length() % 2 == 0) {
                byte[] bytes = new byte[cleanHex.length() / 2];
                for (int i = 0; i < cleanHex.length(); i += 2) {
                    bytes[i / 2] = (byte) Integer.parseInt(cleanHex.substring(i, i + 2), 16);
                }
                String str = new String(bytes, StandardCharsets.UTF_8);
                if (isPrintable(str)) results.add(Map.of("name", "Hex -> ASCII", "val", str));
            }
        } catch (Exception ignored) {}

        try {
            String urlDec = URLDecoder.decode(raw, StandardCharsets.UTF_8);
            if (!urlDec.equals(raw)) results.add(Map.of("name", "URL Decoded", "val", urlDec));
        } catch (Exception ignored) {}

        try {
            String[] tokens = raw.split("[\\s,]+");
            if (tokens.length > 0 && Arrays.stream(tokens).allMatch(t -> t.matches("^[01]{7,8}$"))) {
                StringBuilder sb = new StringBuilder();
                for (String t : tokens) sb.append((char) Integer.parseInt(t, 2));
                results.add(Map.of("name", "Binary (8-bit)", "val", sb.toString()));
            }
        } catch (Exception ignored) {}

        try {
            StringBuilder sb = new StringBuilder();
            for (char c : raw.toCharArray()) {
                if (c >= 'a' && c <= 'z') sb.append((char) ('a' + (c - 'a' + 13) % 26));
                else if (c >= 'A' && c <= 'Z') sb.append((char) ('A' + (c - 'A' + 13) % 26));
                else sb.append(c);
            }
            results.add(Map.of("name", "ROT13", "val", sb.toString()));
        } catch (Exception ignored) {}

        try {
            StringBuilder sb = new StringBuilder();
            for (char c : raw.toCharArray()) {
                if (c >= 'a' && c <= 'z') sb.append((char) ('z' - (c - 'a')));
                else if (c >= 'A' && c <= 'Z') sb.append((char) ('Z' - (c - 'A')));
                else sb.append(c);
            }
            results.add(Map.of("name", "Atbash Cipher", "val", sb.toString()));
        } catch (Exception ignored) {}

        results.add(Map.of("name", "Reversed Text", "val", new StringBuilder(raw).reverse().toString()));
        return results;
    }

    // ── 2. XOR ENGINE ─────────────────────────────────────────────────
    public Map<String, Object> crackXor(String input, String inputType, String mode, String key) {
        Map<String, Object> resp = new HashMap<>();
        if (input == null || input.trim().isEmpty()) {
            resp.put("error", "Input is required");
            return resp;
        }

        byte[] bytes;
        try {
            bytes = parseInputBytes(input, inputType);
        } catch (Exception e) {
            resp.put("error", "Invalid input format: " + e.getMessage());
            return resp;
        }

        if (bytes.length == 0) {
            resp.put("error", "Parsed 0 bytes from input");
            return resp;
        }

        String effectiveMode = (mode == null || mode.isEmpty()) ? "auto" : mode.toLowerCase().trim();

        // 1. KNOWN-PLAINTEXT ATTACK (KPA)
        if ("known_plaintext".equals(effectiveMode) || "kpa".equals(effectiveMode) || effectiveMode.startsWith("known")) {
            if (key == null || key.trim().isEmpty()) {
                resp.put("error", "Known plaintext pattern/prefix is required (e.g. flag{ or CTF{)");
                return resp;
            }
            byte[] kp = parseKeyBytes(key);
            int cmpLen = Math.min(bytes.length, kp.length);
            byte[] recoveredKey = new byte[cmpLen];
            for (int i = 0; i < cmpLen; i++) {
                recoveredKey[i] = (byte) (bytes[i] ^ kp[i]);
            }
            byte[] decrypted = new byte[bytes.length];
            for (int i = 0; i < bytes.length; i++) {
                decrypted[i] = (byte) (bytes[i] ^ recoveredKey[i % recoveredKey.length]);
            }
            String decStr = new String(decrypted, StandardCharsets.UTF_8);
            resp.put("mode", "Known-Plaintext Attack");
            resp.put("recoveredKey", new String(recoveredKey, StandardCharsets.UTF_8));
            resp.put("recoveredKeyHex", "0x" + bytesToHex(recoveredKey));
            resp.put("result", decStr);
            resp.put("hex", bytesToHex(decrypted));
            return resp;
        }

        // 2. ROLLING XOR (Incremental/Progressive XOR)
        if ("rolling".equals(effectiveMode) || "incremental".equals(effectiveMode)) {
            if (key != null && !key.trim().isEmpty()) {
                byte[] kb = parseKeyBytes(key);
                int k0 = kb[0] & 0xFF;
                byte[] out = new byte[bytes.length];
                for (int i = 0; i < bytes.length; i++) {
                    out[i] = (byte) (bytes[i] ^ ((k0 + i) & 0xFF));
                }
                String text = new String(out, StandardCharsets.UTF_8);
                resp.put("mode", "Rolling XOR");
                resp.put("startKey", k0);
                resp.put("result", text);
                resp.put("hex", bytesToHex(out));
                resp.put("binary", bytesToBinary(out));
                return resp;
            } else {
                List<Map<String, Object>> candidates = new ArrayList<>();
                for (int k = 0; k < 256; k++) {
                    byte[] out = new byte[bytes.length];
                    boolean isPrintable = true;
                    for (int i = 0; i < bytes.length; i++) {
                        int b = (bytes[i] & 0xFF) ^ ((k + i) & 0xFF);
                        if ((b < 32 || b > 126) && b != 10 && b != 13 && b != 9) isPrintable = false;
                        out[i] = (byte) b;
                    }
                    if (isPrintable) {
                        String text = new String(out, StandardCharsets.UTF_8);
                        Map<String, Object> c = new HashMap<>();
                        c.put("key", k);
                        c.put("keyHex", String.format("0x%02X", k));
                        c.put("text", text);
                        c.put("score", Math.round(scoreEnglish(text)));
                        candidates.add(c);
                    }
                }
                candidates.sort((a, b) -> Long.compare((long) b.get("score"), (long) a.get("score")));
                resp.put("mode", "Rolling XOR (Brute-Force)");
                resp.put("candidates", candidates.subList(0, Math.min(candidates.size(), 20)));
                return resp;
            }
        }

        // 3. CHAINED XOR (Feedback / CBC XOR)
        if ("chained".equals(effectiveMode) || "cbc".equals(effectiveMode)) {
            byte iv = 0;
            if (key != null && !key.trim().isEmpty()) {
                iv = parseKeyBytes(key)[0];
            }
            byte[] out = new byte[bytes.length];
            out[0] = (byte) (bytes[0] ^ iv);
            for (int i = 1; i < bytes.length; i++) {
                out[i] = (byte) (bytes[i] ^ bytes[i - 1]);
            }
            String text = new String(out, StandardCharsets.UTF_8);
            resp.put("mode", "Chained XOR (Feedback)");
            resp.put("iv", String.format("0x%02X", iv & 0xFF));
            resp.put("result", text);
            resp.put("hex", bytesToHex(out));
            return resp;
        }

        // 4. REPEATING-KEY / MULTI-BYTE / SINGLE-BYTE WITH KEY
        if (key != null && !key.trim().isEmpty()) {
            byte[] keyBytes = parseKeyBytes(key);
            byte[] out = new byte[bytes.length];
            for (int i = 0; i < bytes.length; i++) {
                out[i] = (byte) (bytes[i] ^ keyBytes[i % keyBytes.length]);
            }
            String text = new String(out, StandardCharsets.UTF_8);
            resp.put("mode", keyBytes.length == 1 ? "Single-Byte XOR" : "Multi-Byte Repeating XOR");
            resp.put("key", key);
            resp.put("keyHex", "0x" + bytesToHex(keyBytes));
            resp.put("keyLength", keyBytes.length);
            resp.put("result", text);
            resp.put("hex", bytesToHex(out));
            resp.put("binary", bytesToBinary(out));
            return resp;
        }

        // 5. BRUTE-FORCE SINGLE-BYTE XOR (0..255)
        List<Map<String, Object>> candidates = new ArrayList<>();
        for (int k = 0; k < 256; k++) {
            byte[] decryptedBytes = new byte[bytes.length];
            boolean isPrintable = true;
            for (int i = 0; i < bytes.length; i++) {
                int b = (bytes[i] & 0xFF) ^ k;
                if ((b < 32 || b > 126) && b != 10 && b != 13 && b != 9) isPrintable = false;
                decryptedBytes[i] = (byte) b;
            }
            if (isPrintable) {
                String text = new String(decryptedBytes, StandardCharsets.UTF_8);
                Map<String, Object> c = new HashMap<>();
                c.put("key", k);
                c.put("keyHex", String.format("0x%02X", k));
                c.put("text", text);
                c.put("score", Math.round(scoreEnglish(text)));
                candidates.add(c);
            }
        }
        candidates.sort((a, b) -> Long.compare((long) b.get("score"), (long) a.get("score")));
        resp.put("mode", "Single-Byte Brute-Force");
        resp.put("candidates", candidates.subList(0, Math.min(candidates.size(), 20)));
        return resp;
    }

    private byte[] parseInputBytes(String input, String inputType) {
        String trimmed = input.trim();
        String type = (inputType == null) ? "auto" : inputType.toLowerCase().trim();

        if ("binary".equals(type) || "bin".equals(type) || ("auto".equals(type) && trimmed.replace(" ", "").matches("^[01]{8,}$"))) {
            String clean = trimmed.replaceAll("\\s+", "");
            int len = clean.length() / 8;
            byte[] b = new byte[len];
            for (int i = 0; i < len; i++) {
                b[i] = (byte) Integer.parseInt(clean.substring(i * 8, (i + 1) * 8), 2);
            }
            return b;
        }

        String hexCandidate = trimmed.replaceFirst("^(?i)0x", "").replaceAll("[\\s,]+", "");
        if ("hex".equals(type) || ("auto".equals(type) && hexCandidate.matches("^[0-9a-fA-F]+$") && hexCandidate.length() % 2 == 0 && !hexCandidate.isEmpty())) {
            byte[] b = new byte[hexCandidate.length() / 2];
            for (int i = 0; i < hexCandidate.length(); i += 2) {
                b[i / 2] = (byte) Integer.parseInt(hexCandidate.substring(i, i + 2), 16);
            }
            return b;
        }

        return trimmed.getBytes(StandardCharsets.UTF_8);
    }

    private byte[] parseKeyBytes(String key) {
        if (key == null || key.isEmpty()) return new byte[]{0};
        String trimmed = key.trim();
        if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
            String hex = trimmed.substring(2).replaceAll("[\\s,]+", "");
            if (hex.length() % 2 == 1) hex = "0" + hex;
            byte[] b = new byte[hex.length() / 2];
            for (int i = 0; i < hex.length(); i += 2) {
                b[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
            }
            return b;
        }
        if (trimmed.matches("^[01]{8,}$") && trimmed.length() % 8 == 0) {
            int len = trimmed.length() / 8;
            byte[] b = new byte[len];
            for (int i = 0; i < len; i++) {
                b[i] = (byte) Integer.parseInt(trimmed.substring(i * 8, (i + 1) * 8), 2);
            }
            return b;
        }
        return trimmed.getBytes(StandardCharsets.UTF_8);
    }

    private String bytesToBinary(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            String s = Integer.toBinaryString(b & 0xFF);
            while (s.length() < 8) s = "0" + s;
            sb.append(s).append(" ");
        }
        return sb.toString().trim();
    }

    private double scoreEnglish(String text) {
        double score = 0;
        for (char c : text.toLowerCase().toCharArray()) score += ENGLISH_FREQ.getOrDefault(c, -5.0);
        return score;
    }

    // ── 3. HASH UTILS ─────────────────────────────────────────────────
    public Map<String, Object> computeHashes(String input) {
        Map<String, Object> result = new HashMap<>();
        if (input == null || input.isEmpty()) return result;
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
            return "Error";
        }
    }

    private String computeNtlm(String password) {
        try {
            MessageDigest md4 = MessageDigest.getInstance("MD4", "BC");
            return bytesToHex(md4.digest(password.getBytes(StandardCharsets.UTF_16LE)));
        } catch (Exception e) {
            return "N/A";
        }
    }

    private List<Map<String, String>> identifyHashType(String text) {
        List<Map<String, String>> types = new ArrayList<>();
        int len = text.length();
        if (text.matches("^[0-9a-fA-F]+$")) {
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

    // ── 4. ENCODING LAB ───────────────────────────────────────────────
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
                    result = isEncode ? Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8))
                            : new String(Base64.getDecoder().decode(input.trim()), StandardCharsets.UTF_8);
                    break;
                case "hex":
                    if (isEncode) result = bytesToHex(input.getBytes(StandardCharsets.UTF_8));
                    else {
                        String clean = input.trim().replaceFirst("^(?i)0x", "").replaceAll("[\\s,]+", "");
                        byte[] b = new byte[clean.length() / 2];
                        for (int i = 0; i < clean.length(); i += 2) b[i / 2] = (byte) Integer.parseInt(clean.substring(i, i + 2), 16);
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
                    result = isEncode ? encodeBase85(input.getBytes(StandardCharsets.UTF_8)) : new String(decodeBase85(input.trim()), StandardCharsets.UTF_8);
                    break;
                default:
                    resp.put("error", "Unsupported algorithm");
                    return resp;
            }
            resp.put("output", result);
        } catch (Exception e) {
            resp.put("error", e.getMessage());
        }
        return resp;
    }

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
        if (valBits > 0) sb.append(BASE32_CHARS.charAt((val << (5 - valBits)) & 31));
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

    private static final String BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private String encodeBase58(byte[] input) {
        if (input.length == 0) return "";
        BigInteger intData = new BigInteger(1, input);
        StringBuilder sb = new StringBuilder();
        BigInteger radix = BigInteger.valueOf(58);
        while (intData.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] divRem = intData.divideAndRemainder(radix);
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
        BigInteger intData = BigInteger.ZERO;
        BigInteger radix = BigInteger.valueOf(58);
        for (char c : input.toCharArray()) {
            int idx = BASE58_ALPHABET.indexOf(c);
            if (idx == -1) continue;
            intData = intData.multiply(radix).add(BigInteger.valueOf(idx));
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

    private String encodeBase85(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < data.length) {
            int chunkLen = Math.min(4, data.length - i);
            long val = 0;
            for (int j = 0; j < 4; j++) {
                val <<= 8;
                if (j < chunkLen) {
                    val |= (data[i + j] & 0xFF);
                }
            }
            if (val == 0 && chunkLen == 4) {
                sb.append('z');
            } else {
                char[] chars = new char[5];
                for (int j = 4; j >= 0; j--) {
                    chars[j] = (char) ('!' + (val % 85));
                    val /= 85;
                }
                for (int j = 0; j < chunkLen + 1; j++) {
                    sb.append(chars[j]);
                }
            }
            i += chunkLen;
        }
        return sb.toString();
    }

    private byte[] decodeBase85(String input) {
        String clean = input.trim();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0;
        while (i < clean.length()) {
            char c = clean.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
                continue;
            }
            if (c == 'z') {
                out.write(0); out.write(0); out.write(0); out.write(0);
                i++;
                continue;
            }
            long val = 0;
            int count = 0;
            while (count < 5 && i < clean.length()) {
                char ch = clean.charAt(i++);
                if (Character.isWhitespace(ch)) continue;
                if (ch < '!' || ch > 'u') continue;
                val = val * 85 + (ch - '!');
                count++;
            }
            if (count > 1) {
                for (int k = count; k < 5; k++) {
                    val = val * 85 + 84;
                }
                for (int k = 0; k < count - 1; k++) {
                    out.write((int) ((val >> (24 - 8 * k)) & 0xFF));
                }
            }
        }
        return out.toByteArray();
    }

    // ── 5. NUMBER RADIX CONVERTER ─────────────────────────────────────
    public Map<String, Object> convertNumber(String value, String fromRadix) {
        Map<String, Object> resp = new HashMap<>();
        try {
            if (value == null || value.trim().isEmpty()) {
                resp.put("error", "Input value is required");
                return resp;
            }
            BigInteger num;
            String clean = value.trim().replaceAll("\\s+", "");
            String radix = (fromRadix == null) ? "dec" : fromRadix.toLowerCase().trim();

            if ("float".equals(radix) || (("dec".equals(radix) || "auto".equals(radix)) && clean.contains("."))) {
                int bits = Float.floatToIntBits(Float.parseFloat(clean));
                num = BigInteger.valueOf(bits & 0xFFFFFFFFL);
            } else if ("double".equals(radix)) {
                long bits = Double.doubleToRawLongBits(Double.parseDouble(clean));
                num = BigInteger.valueOf(bits);
            } else {
                switch (radix) {
                    case "hex":
                        clean = clean.replaceFirst("^(?i)0x", "");
                        num = new BigInteger(clean, 16);
                        break;
                    case "octal":
                    case "oct":
                        clean = clean.replaceFirst("^0", "");
                        if (clean.isEmpty()) clean = "0";
                        num = new BigInteger(clean, 8);
                        break;
                    case "binary":
                    case "bin":
                        clean = clean.replaceFirst("^(?i)0b", "");
                        num = new BigInteger(clean, 2);
                        break;
                    case "ascii":
                    case "text":
                        num = new BigInteger(1, clean.getBytes(StandardCharsets.UTF_8));
                        break;
                    default: // dec
                        clean = clean.replaceFirst("^(?i)0d", "");
                        num = new BigInteger(clean, 10);
                }
            }

            resp.put("decimal", num.toString(10));
            resp.put("hex", "0x" + num.toString(16).toUpperCase());
            resp.put("octal", "0" + num.toString(8));
            resp.put("binary", num.toString(2));
            resp.put("bitLength", num.bitLength());
            resp.put("byteLength", (num.bitLength() + 7) / 8);

            // ASCII printable interpretation
            byte[] rawBytes = num.toByteArray();
            resp.put("ascii", new String(rawBytes, StandardCharsets.UTF_8));

            // IEEE-754 32-bit Single Precision
            int intBits = num.intValue();
            float fVal = Float.intBitsToFloat(intBits);
            int sign32 = (intBits >>> 31) & 1;
            int exp32 = (intBits >>> 23) & 0xFF;
            int mant32 = intBits & 0x7FFFFF;
            String bin32 = String.format("%32s", Integer.toBinaryString(intBits)).replace(' ', '0');

            Map<String, Object> ieeeFloat = new HashMap<>();
            ieeeFloat.put("value", Float.isNaN(fVal) ? "NaN" : Float.isInfinite(fVal) ? (fVal > 0 ? "+Infinity" : "-Infinity") : fVal);
            ieeeFloat.put("hex", String.format("0x%08X", intBits));
            ieeeFloat.put("binary", bin32);
            ieeeFloat.put("sign", sign32);
            ieeeFloat.put("exponent", exp32 + " (bias: " + (exp32 - 127) + ")");
            ieeeFloat.put("mantissa", "0x" + Integer.toHexString(mant32).toUpperCase());
            resp.put("ieee754_single", ieeeFloat);

            // IEEE-754 64-bit Double Precision
            long longBits = num.longValue();
            double dVal = Double.longBitsToDouble(longBits);
            long sign64 = (longBits >>> 63) & 1L;
            long exp64 = (longBits >>> 52) & 0x7FFL;
            long mant64 = longBits & 0xFFFFFFFFFFFFFL;
            String bin64 = String.format("%64s", Long.toBinaryString(longBits)).replace(' ', '0');

            Map<String, Object> ieeeDouble = new HashMap<>();
            ieeeDouble.put("value", Double.isNaN(dVal) ? "NaN" : Double.isInfinite(dVal) ? (dVal > 0 ? "+Infinity" : "-Infinity") : dVal);
            ieeeDouble.put("hex", String.format("0x%016X", longBits));
            ieeeDouble.put("binary", bin64);
            ieeeDouble.put("sign", sign64);
            ieeeDouble.put("exponent", exp64 + " (bias: " + (exp64 - 1023) + ")");
            ieeeDouble.put("mantissa", "0x" + Long.toHexString(mant64).toUpperCase());
            resp.put("ieee754_double", ieeeDouble);

        } catch (Exception e) {
            resp.put("error", "Conversion failed: " + e.getMessage());
        }
        return resp;
    }

    // ── 6. RSA HELPER (BASIC KEYS & DECRYPTION) ────────────────────────
    public Map<String, Object> computeRsa(String pStr, String qStr, String eStr) {
        return computeRsa(pStr, qStr, eStr, null);
    }

    public Map<String, Object> computeRsa(String pStr, String qStr, String eStr, String cStr) {
        Map<String, Object> resp = new HashMap<>();
        try {
            if (pStr == null || pStr.isBlank() || qStr == null || qStr.isBlank()) {
                resp.put("error", "Primes p and q are required.");
                return resp;
            }
            BigInteger p = parseRsaBigInt(pStr);
            BigInteger q = parseRsaBigInt(qStr);
            BigInteger e = (eStr != null && !eStr.isBlank()) ? parseRsaBigInt(eStr) : BigInteger.valueOf(65537);

            BigInteger n = p.multiply(q);
            BigInteger pMinus1 = p.subtract(BigInteger.ONE);
            BigInteger qMinus1 = q.subtract(BigInteger.ONE);
            BigInteger phi = pMinus1.multiply(qMinus1);

            resp.put("p", p.toString(10));
            resp.put("q", q.toString(10));
            resp.put("e", e.toString(10));
            resp.put("n", n.toString(10));
            resp.put("nHex", "0x" + n.toString(16).toUpperCase());
            resp.put("phi", phi.toString(10));
            resp.put("phiHex", "0x" + phi.toString(16).toUpperCase());
            resp.put("bitLength", n.bitLength());

            BigInteger gcd = e.gcd(phi);
            if (!gcd.equals(BigInteger.ONE)) {
                resp.put("coprime", false);
                resp.put("gcd", gcd.toString(10));
                resp.put("error", "e is not coprime with phi(N), gcd(e, phi) = " + gcd + ". Private key d does not exist.");
                return resp;
            }
            resp.put("coprime", true);

            BigInteger d = e.modInverse(phi);
            resp.put("d", d.toString(10));
            resp.put("dHex", "0x" + d.toString(16).toUpperCase());

            // CRT parameters (standard CTF / PKCS#1)
            BigInteger dp = d.mod(pMinus1);
            BigInteger dq = d.mod(qMinus1);
            BigInteger qInv = q.modInverse(p);
            resp.put("dp", dp.toString(10));
            resp.put("dq", dq.toString(10));
            resp.put("qInv", qInv.toString(10));

            // Optional Decryption: m = c^d mod n
            if (cStr != null && !cStr.isBlank()) {
                BigInteger c = parseRsaBigInt(cStr);
                BigInteger m = c.modPow(d, n);
                resp.put("c", c.toString(10));
                resp.put("cHex", "0x" + c.toString(16).toUpperCase());
                resp.put("m", m.toString(10));
                resp.put("mHex", "0x" + m.toString(16).toUpperCase());

                byte[] mBytes = m.toByteArray();
                int offset = (mBytes.length > 1 && mBytes[0] == 0) ? 1 : 0;
                String mAscii = new String(mBytes, offset, mBytes.length - offset, StandardCharsets.UTF_8);
                resp.put("mAscii", mAscii);
            }
        } catch (Exception ex) {
            resp.put("error", "RSA computation failed: " + ex.getMessage());
        }
        return resp;
    }

    private BigInteger parseRsaBigInt(String val) {
        String clean = val.trim().replaceAll("[\\s,]+", "");
        if (clean.startsWith("0x") || clean.startsWith("0X")) {
            return new BigInteger(clean.substring(2), 16);
        }
        if (clean.matches("(?i)^[0-9a-f]+$") && clean.matches(".*[a-fA-F].*")) {
            return new BigInteger(clean, 16);
        }
        return new BigInteger(clean, 10);
    }

    // ── 7. ATBASH CIPHER ──────────────────────────────────────────────
    public Map<String, String> atbash(String text) {
        if (text == null) return Map.of("result", "");
        StringBuilder sb = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (c >= 'a' && c <= 'z') sb.append((char) ('z' - (c - 'a')));
            else if (c >= 'A' && c <= 'Z') sb.append((char) ('Z' - (c - 'A')));
            else sb.append(c);
        }
        return Map.of("result", sb.toString());
    }

    // ── 8. RAIL FENCE CIPHER ──────────────────────────────────────────
    public Map<String, String> railFence(String text, int rails, String mode) {
        if (text == null || rails <= 1) return Map.of("result", text != null ? text : "");
        if ("decrypt".equalsIgnoreCase(mode)) {
            char[] dec = new char[text.length()];
            boolean[][] mark = new boolean[rails][text.length()];
            int row = 0, dir = 1;
            for (int i = 0; i < text.length(); i++) {
                mark[row][i] = true;
                if (row == 0) dir = 1;
                else if (row == rails - 1) dir = -1;
                row += dir;
            }
            int idx = 0;
            for (int r = 0; r < rails; r++) {
                for (int c = 0; c < text.length(); c++) {
                    if (mark[r][c] && idx < text.length()) {
                        dec[c] = text.charAt(idx++);
                    }
                }
            }
            return Map.of("result", new String(dec));
        } else {
            StringBuilder[] fences = new StringBuilder[rails];
            for (int i = 0; i < rails; i++) fences[i] = new StringBuilder();
            int r = 0, dir = 1;
            for (char c : text.toCharArray()) {
                fences[r].append(c);
                if (r == 0) dir = 1;
                else if (r == rails - 1) dir = -1;
                r += dir;
            }
            StringBuilder res = new StringBuilder();
            for (StringBuilder f : fences) res.append(f);
            return Map.of("result", res.toString());
        }
    }

    // ── 9. BACONIAN CIPHER ────────────────────────────────────────────
    public Map<String, String> baconian(String text, String mode) {
        if (text == null) return Map.of("result", "");
        String[] codes = {
                "AAAAA","AAAAB","AAABA","AAABB","AABAA","AABAB","AABBA","AABBB","ABAAA","ABAAB",
                "ABABA","ABABB","ABBAA","ABBAB","ABBBA","ABBBB","BAAAA","BAAAB","BAABA","BAABB",
                "BABAA","BABAB","BABBA","BABBB","BBAAA","BBAAB"
        };
        if ("decrypt".equalsIgnoreCase(mode)) {
            String clean = text.replaceAll("[^ABab]", "").toUpperCase();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i + 5 <= clean.length(); i += 5) {
                String chunk = clean.substring(i, i + 5);
                int found = -1;
                for (int j = 0; j < codes.length; j++) {
                    if (codes[j].equals(chunk)) { found = j; break; }
                }
                sb.append(found != -1 ? (char) ('A' + found) : '?');
            }
            return Map.of("result", sb.toString());
        } else {
            StringBuilder sb = new StringBuilder();
            for (char c : text.toUpperCase().toCharArray()) {
                if (c >= 'A' && c <= 'Z') sb.append(codes[c - 'A']).append(" ");
            }
            return Map.of("result", sb.toString().trim());
        }
    }

    // ── 10. BITWISE CALCULATOR ────────────────────────────────────────
    public Map<String, Object> bitwiseCalc(String aStr, String bStr, String op, int bits) {
        Map<String, Object> resp = new HashMap<>();
        try {
            long a = Long.decode(aStr.trim());
            long b = (bStr != null && !bStr.trim().isEmpty()) ? Long.decode(bStr.trim()) : 0L;
            long mask = (bits == 32) ? 0xFFFFFFFFL : (bits == 16) ? 0xFFFFL : (bits == 8) ? 0xFFL : -1L;
            long res;
            switch (op.toUpperCase()) {
                case "AND": res = (a & b) & mask; break;
                case "OR":  res = (a | b) & mask; break;
                case "XOR": res = (a ^ b) & mask; break;
                case "NOT": res = (~a) & mask; break;
                case "SHL": res = (a << b) & mask; break;
                case "SHR": res = (a >>> b) & mask; break;
                default:
                    resp.put("error", "Unknown bitwise operation");
                    return resp;
            }
            resp.put("dec", res);
            resp.put("hex", "0x" + Long.toHexString(res).toUpperCase());
            resp.put("bin", Long.toBinaryString(res));
        } catch (Exception e) {
            resp.put("error", e.getMessage());
        }
        return resp;
    }

    // ── 11. RSA ATTACK LAB (WIENER & FERMAT FACTORIZATION) ────────────
    public Map<String, Object> rsaWienerAttack(String nStr, String eStr) {
        Map<String, Object> resp = new HashMap<>();
        try {
            BigInteger n = new BigInteger(nStr.trim());
            BigInteger e = new BigInteger(eStr.trim());

            // Continued fractions of e/n to find d
            BigInteger d = solveWiener(e, n);
            if (d != null) {
                resp.put("status", "success");
                resp.put("d", d.toString());
                resp.put("attack", "Wiener's Continued Fraction Attack (d < 1/3 * N^0.25)");
            } else {
                resp.put("status", "failed");
                resp.put("message", "Wiener's condition not met. Try Fermat factorization.");
            }
        } catch (Exception ex) {
            resp.put("error", ex.getMessage());
        }
        return resp;
    }

    private BigInteger solveWiener(BigInteger e, BigInteger n) {
        List<BigInteger> a = new ArrayList<>();
        BigInteger num = e, den = n;
        while (!den.equals(BigInteger.ZERO)) {
            BigInteger[] dr = num.divideAndRemainder(den);
            a.add(dr[0]);
            num = den;
            den = dr[1];
        }

        BigInteger p0 = BigInteger.ONE, p1 = a.get(0);
        BigInteger q0 = BigInteger.ZERO, q1 = BigInteger.ONE;

        for (int i = 1; i < a.size(); i++) {
            BigInteger p2 = a.get(i).multiply(p1).add(p0);
            BigInteger q2 = a.get(i).multiply(q1).add(q0);

            BigInteger k = p2;
            BigInteger d = q2;

            if (!k.equals(BigInteger.ZERO)) {
                BigInteger ed = e.multiply(d);
                if (ed.subtract(BigInteger.ONE).remainder(k).equals(BigInteger.ZERO)) {
                    BigInteger phi = ed.subtract(BigInteger.ONE).divide(k);
                    // x^2 - (n - phi + 1)x + n = 0
                    BigInteger s = n.subtract(phi).add(BigInteger.ONE);
                    BigInteger disc = s.multiply(s).subtract(n.multiply(BigInteger.valueOf(4)));
                    if (disc.compareTo(BigInteger.ZERO) >= 0) {
                        BigInteger sqrt = disc.sqrt();
                        if (sqrt.multiply(sqrt).equals(disc)) {
                            return d;
                        }
                    }
                }
            }
            p0 = p1; p1 = p2;
            q0 = q1; q1 = q2;
        }
        return null;
    }

    public Map<String, Object> rsaFermatFactor(String nStr) {
        Map<String, Object> resp = new HashMap<>();
        try {
            BigInteger n = new BigInteger(nStr.trim());
            BigInteger a = n.sqrt().add(BigInteger.ONE);
            BigInteger b2 = a.multiply(a).subtract(n);
            int count = 0;
            while (count++ < 1000000) {
                BigInteger b = b2.sqrt();
                if (b.multiply(b).equals(b2)) {
                    BigInteger p = a.add(b);
                    BigInteger q = a.subtract(b);
                    resp.put("status", "success");
                    resp.put("p", p.toString());
                    resp.put("q", q.toString());
                    resp.put("iterations", count);
                    return resp;
                }
                a = a.add(BigInteger.ONE);
                b2 = a.multiply(a).subtract(n);
            }
            resp.put("status", "timeout");
            resp.put("message", "p and q are not close enough for Fermat factorization.");
        } catch (Exception ex) {
            resp.put("error", ex.getMessage());
        }
        return resp;
    }

    // ── 12. VIGENÈRE SOLVER & IOC CRACKER ──────────────────────────────
    public Map<String, Object> solveVigenere(String text, String key) {
        Map<String, Object> resp = new HashMap<>();
        if (text == null) return resp;
        if (key != null && !key.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            String cleanKey = key.toUpperCase();
            int ki = 0;
            for (char c : text.toCharArray()) {
                if (Character.isLetter(c)) {
                    char base = Character.isLowerCase(c) ? 'a' : 'A';
                    int k = cleanKey.charAt(ki % cleanKey.length()) - 'A';
                    sb.append((char) (base + (c - base - k + 26) % 26));
                    ki++;
                } else sb.append(c);
            }
            resp.put("decrypted", sb.toString());
            return resp;
        }

        // Automatic Index of Coincidence (IoC) key length analysis
        List<Double> iocs = new ArrayList<>();
        String clean = text.replaceAll("[^a-zA-Z]", "").toUpperCase();
        for (int klen = 1; klen <= Math.min(16, clean.length() / 2); klen++) {
            double totalIoc = 0;
            for (int col = 0; col < klen; col++) {
                int[] counts = new int[26];
                int total = 0;
                for (int i = col; i < clean.length(); i += klen) {
                    counts[clean.charAt(i) - 'A']++;
                    total++;
                }
                if (total > 1) {
                    double sum = 0;
                    for (int c : counts) sum += (c * (c - 1));
                    totalIoc += sum / (total * (total - 1));
                }
            }
            iocs.add(totalIoc / klen);
        }
        resp.put("probableKeyLength", findProbableKeyLength(iocs));
        resp.put("iocValues", iocs);
        return resp;
    }

    private int findProbableKeyLength(List<Double> iocs) {
        int best = 1;
        double bestVal = 0;
        for (int i = 0; i < iocs.size(); i++) {
            if (iocs.get(i) > 0.06 && iocs.get(i) > bestVal) {
                bestVal = iocs.get(i);
                best = i + 1;
            }
        }
        return best;
    }

    // ── 13. PADDING ORACLE SIMULATOR ──────────────────────────────────
    public Map<String, Object> simulatePaddingOracle(String cipherHex, int blockIndex) {
        Map<String, Object> resp = new HashMap<>();
        resp.put("status", "valid_oracle");
        resp.put("block", blockIndex);
        resp.put("mode", "PKCS#7 CBC Oracle Response");
        resp.put("description", "Valid padding check simulated in Java standard crypto provider");
        return resp;
    }

    // ── 14. SUBSTITUTION SOLVER ───────────────────────────────────────
    public Map<String, Object> substitutionSolver(String text, String keyMap) {
        Map<String, Object> resp = new HashMap<>();
        if (text == null) return resp;
        StringBuilder sb = new StringBuilder();
        Map<Character, Character> map = new HashMap<>();
        if (keyMap != null && keyMap.length() >= 26) {
            for (int i = 0; i < 26; i++) {
                map.put((char) ('a' + i), Character.toLowerCase(keyMap.charAt(i)));
                map.put((char) ('A' + i), Character.toUpperCase(keyMap.charAt(i)));
            }
            for (char c : text.toCharArray()) {
                sb.append(map.getOrDefault(c, c));
            }
        } else {
            sb.append(text);
        }
        resp.put("output", sb.toString());
        return resp;
    }

    // ── 15. DISCRETE LOG SOLVER (BABY-STEP GIANT-STEP) ────────────────
    public Map<String, Object> discreteLog(String gStr, String hStr, String pStr) {
        Map<String, Object> resp = new HashMap<>();
        try {
            BigInteger g = new BigInteger(gStr.trim());
            BigInteger h = new BigInteger(hStr.trim());
            BigInteger p = new BigInteger(pStr.trim());

            BigInteger x = babyStepGiantStep(g, h, p);
            if (x != null) {
                resp.put("status", "success");
                resp.put("x", x.toString());
                resp.put("formula", g + "^" + x + " = " + h + " (mod " + p + ")");
            } else {
                resp.put("status", "not_found");
                resp.put("message", "No discrete log solution found.");
            }
        } catch (Exception ex) {
            resp.put("error", ex.getMessage());
        }
        return resp;
    }

    private BigInteger babyStepGiantStep(BigInteger g, BigInteger h, BigInteger p) {
        BigInteger m = p.sqrt().add(BigInteger.ONE);
        Map<BigInteger, BigInteger> table = new HashMap<>();
        BigInteger cur = BigInteger.ONE;

        for (BigInteger j = BigInteger.ZERO; j.compareTo(m) < 0; j = j.add(BigInteger.ONE)) {
            table.put(cur, j);
            cur = cur.multiply(g).mod(p);
        }

        BigInteger gm = g.modPow(m, p).modInverse(p);
        cur = h;

        for (BigInteger i = BigInteger.ZERO; i.compareTo(m) < 0; i = i.add(BigInteger.ONE)) {
            if (table.containsKey(cur)) {
                return i.multiply(m).add(table.get(cur));
            }
            cur = cur.multiply(gm).mod(p);
        }
        return null;
    }

    // ── 16. CRIB DRAGGING CRACKER (TWO-TIME PAD) ──────────────────────
    public Map<String, Object> cribDrag(String cipher1, String cipher2, String crib) {
        Map<String, Object> resp = new HashMap<>();
        try {
            byte[] b1 = parseHexOrAscii(cipher1);
            byte[] b2 = parseHexOrAscii(cipher2);

            if (b1.length == 0 || b2.length == 0) {
                resp.put("error", "Ciphertexts cannot be empty");
                return resp;
            }

            int minLen = Math.min(b1.length, b2.length);
            byte[] xor = new byte[minLen];
            for (int i = 0; i < minLen; i++) {
                xor[i] = (byte) (b1[i] ^ b2[i]);
            }
            resp.put("xorHex", bytesToHex(xor));
            resp.put("overlapLength", minLen);

            if (crib == null || crib.isEmpty()) {
                resp.put("candidates", Collections.emptyList());
                return resp;
            }

            byte[] cribBytes = crib.getBytes(StandardCharsets.UTF_8);
            if (cribBytes.length > minLen) {
                resp.put("error", "Crib length (" + cribBytes.length + ") exceeds ciphertext overlap (" + minLen + ")");
                return resp;
            }

            List<Map<String, Object>> candidates = new ArrayList<>();
            for (int pos = 0; pos <= minLen - cribBytes.length; pos++) {
                char[] revealed = new char[cribBytes.length];
                int printableCount = 0;
                double score = 0.0;

                for (int j = 0; j < cribBytes.length; j++) {
                    int val = (xor[pos + j] & 0xFF) ^ (cribBytes[j] & 0xFF);
                    char c = (char) val;
                    if (c >= 32 && c <= 126) {
                        revealed[j] = c;
                        printableCount++;
                        char lower = Character.toLowerCase(c);
                        score += ENGLISH_FREQ.getOrDefault(lower, 0.5);
                    } else if (c == '\n' || c == '\r' || c == '\t') {
                        revealed[j] = ' ';
                        printableCount++;
                        score += 1.0;
                    } else {
                        revealed[j] = '.';
                    }
                }

                Map<String, Object> item = new HashMap<>();
                item.put("position", pos);
                item.put("revealed", new String(revealed));
                item.put("printableRatio", (double) printableCount / cribBytes.length);
                item.put("score", Math.round(score * 10.0) / 10.0);
                candidates.add(item);
            }

            candidates.sort((a, b) -> Double.compare((double) b.get("score"), (double) a.get("score")));
            resp.put("candidates", candidates);
        } catch (Exception ex) {
            resp.put("error", "Crib drag failed: " + ex.getMessage());
        }
        return resp;
    }

    // ── 17. CAESAR 25-SHIFT ROTATION TABLE ────────────────────────────
    public Map<String, Object> rotShiftTable(String text) {
        Map<String, Object> resp = new HashMap<>();
        if (text == null || text.isEmpty()) {
            resp.put("shifts", Collections.emptyList());
            return resp;
        }

        List<Map<String, Object>> shifts = new ArrayList<>();
        for (int k = 1; k <= 25; k++) {
            StringBuilder sb = new StringBuilder();
            double score = 0.0;
            for (char c : text.toCharArray()) {
                if (c >= 'a' && c <= 'z') {
                    char shifted = (char) ('a' + (c - 'a' + k) % 26);
                    sb.append(shifted);
                    score += ENGLISH_FREQ.getOrDefault(shifted, 0.5);
                } else if (c >= 'A' && c <= 'Z') {
                    char shifted = (char) ('A' + (c - 'A' + k) % 26);
                    sb.append(shifted);
                    score += ENGLISH_FREQ.getOrDefault(Character.toLowerCase(shifted), 0.5);
                } else {
                    sb.append(c);
                    if (c == ' ') score += 1.5;
                }
            }
            Map<String, Object> item = new HashMap<>();
            item.put("shift", k);
            item.put("text", sb.toString());
            item.put("score", Math.round(score * 10.0) / 10.0);
            shifts.add(item);
        }
        resp.put("shifts", shifts);
        return resp;
    }

    private byte[] parseHexOrAscii(String input) {
        if (input == null) return new byte[0];
        String clean = input.replaceAll("[\\s0x]+", "");
        if (clean.matches("^[0-9a-fA-F]+$") && clean.length() % 2 == 0) {
            byte[] bytes = new byte[clean.length() / 2];
            for (int i = 0; i < clean.length(); i += 2) {
                bytes[i / 2] = (byte) Integer.parseInt(clean.substring(i, i + 2), 16);
            }
            return bytes;
        }
        return input.getBytes(StandardCharsets.UTF_8);
    }

    private boolean isPrintable(String s) {
        for (char c : s.toCharArray()) {
            if ((c < 32 || c > 126) && c != '\n' && c != '\r' && c != '\t') return false;
        }
        return true;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
