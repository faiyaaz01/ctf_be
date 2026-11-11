package com.ctf.platform;

import com.ctf.platform.service.tools.CryptoEngineService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class CryptoEngineServiceTest {

    private CryptoEngineService cryptoEngineService;

    @BeforeEach
    void setUp() {
        cryptoEngineService = new CryptoEngineService();
    }

    @Test
    void testSingleByteXorWithKey() {
        // "flag{test}" XOR '*' (ASCII 42)
        // 'f' ^ 42 = 102 ^ 42 = 76 (0x4c) ... '}' ^ 42 = 125 ^ 42 = 87 (0x57)
        Map<String, Object> res = cryptoEngineService.crackXor("4c464b4d515e4f595e57", "hex", "single", "*");
        assertEquals("flag{test}", res.get("result"));
    }

    @Test
    void testRepeatingKeyMultiByteXor() {
        // "ATTACKATDAWN" XOR "KEY"
        Map<String, Object> enc = cryptoEngineService.crackXor("ATTACKATDAWN", "text", "repeating", "KEY");
        String hex = (String) enc.get("hex");
        assertNotNull(hex);

        // Decrypt back with repeating key
        Map<String, Object> dec = cryptoEngineService.crackXor(hex, "hex", "repeating", "KEY");
        assertEquals("ATTACKATDAWN", dec.get("result"));
    }

    @Test
    void testBruteForceSingleByteXor() {
        // "flag{xor_is_awesome}" XOR 42 = 4c464b4d51524558754359754b5d4f5945474f57
        Map<String, Object> res = cryptoEngineService.crackXor("4c464b4d51524558754359754b5d4f5945474f57", "hex", "brute", "");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> candidates = (List<Map<String, Object>>) res.get("candidates");
        assertNotNull(candidates);
        assertFalse(candidates.isEmpty());
        assertEquals("flag{xor_is_awesome}", candidates.get(0).get("text"));
        assertEquals(42, candidates.get(0).get("key"));
    }

    @Test
    void testKnownPlaintextXor() {
        // Ciphertext: "flag{secret_key}" XOR "SECRETKEY"
        Map<String, Object> enc = cryptoEngineService.crackXor("flag{secret_key}", "text", "repeating", "SECRETKEY");
        String hex = (String) enc.get("hex");

        // Known plaintext prefix: "flag{"
        Map<String, Object> kpa = cryptoEngineService.crackXor(hex, "hex", "known_plaintext", "flag{");
        String recoveredKey = (String) kpa.get("recoveredKey");
        assertEquals("SECRE", recoveredKey);
    }

    @Test
    void testRollingXor() {
        // Rolling XOR: each byte ^ (k + i)
        Map<String, Object> res = cryptoEngineService.crackXor("SECRET_DATA", "text", "rolling", "0x10");
        String hex = (String) res.get("hex");
        assertNotNull(hex);

        // Decrypt with same start key
        Map<String, Object> dec = cryptoEngineService.crackXor(hex, "hex", "rolling", "0x10");
        assertEquals("SECRET_DATA", dec.get("result"));
    }

    @Test
    void testChainedXor() {
        // Chained XOR: C[0] = P[0] ^ IV, C[i] = P[i] ^ C[i-1]
        // Decryption: P[0] = C[0] ^ IV, P[i] = C[i] ^ C[i-1]
        byte[] pt = "CHALLENGE_FLAG".getBytes();
        byte iv = 0x5A;
        byte[] ct = new byte[pt.length];
        ct[0] = (byte) (pt[0] ^ iv);
        for (int i = 1; i < pt.length; i++) {
            ct[i] = (byte) (pt[i] ^ ct[i - 1]);
        }
        StringBuilder hex = new StringBuilder();
        for (byte b : ct) hex.append(String.format("%02x", b));

        Map<String, Object> dec = cryptoEngineService.crackXor(hex.toString(), "hex", "chained", "0x5A");
        assertEquals("CHALLENGE_FLAG", dec.get("result"));
    }

    @Test
    void testBinaryInputXor() {
        // 'A' (01000001) ^ 'B' (01000010) = 00000011 (0x03)
        Map<String, Object> res = cryptoEngineService.crackXor("01000001", "binary", "single", "B");
        assertEquals("03", res.get("hex"));
    }

    @Test
    void testEncodingLabAllFormats() {
        String testStr = "CTF{encoding_lab_success}";

        // Base64
        Map<String, Object> b64Enc = cryptoEngineService.processEncoding(testStr, "base64", "encode");
        Map<String, Object> b64Dec = cryptoEngineService.processEncoding((String) b64Enc.get("output"), "base64", "decode");
        assertEquals(testStr, b64Dec.get("output"));

        // Hex
        Map<String, Object> hexEnc = cryptoEngineService.processEncoding(testStr, "hex", "encode");
        Map<String, Object> hexDec = cryptoEngineService.processEncoding((String) hexEnc.get("output"), "hex", "decode");
        assertEquals(testStr, hexDec.get("output"));

        // Base32
        Map<String, Object> b32Enc = cryptoEngineService.processEncoding(testStr, "base32", "encode");
        Map<String, Object> b32Dec = cryptoEngineService.processEncoding((String) b32Enc.get("output"), "base32", "decode");
        assertEquals(testStr, b32Dec.get("output"));

        // Base58
        Map<String, Object> b58Enc = cryptoEngineService.processEncoding(testStr, "base58", "encode");
        Map<String, Object> b58Dec = cryptoEngineService.processEncoding((String) b58Enc.get("output"), "base58", "decode");
        assertEquals(testStr, b58Dec.get("output"));

        // Base85
        Map<String, Object> b85Enc = cryptoEngineService.processEncoding(testStr, "base85", "encode");
        Map<String, Object> b85Dec = cryptoEngineService.processEncoding((String) b85Enc.get("output"), "base85", "decode");
        assertEquals(testStr, b85Dec.get("output"));
    }
}
