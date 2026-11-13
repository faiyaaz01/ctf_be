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

    @Test
    void testNumberConverterRadixAndIeee754() {
        // Decimal 42 -> Hex 0x2A, Octal 052, Binary 101010, ASCII '*'
        Map<String, Object> decRes = cryptoEngineService.convertNumber("42", "dec");
        assertEquals("42", decRes.get("decimal"));
        assertEquals("0x2A", decRes.get("hex"));
        assertEquals("052", decRes.get("octal"));
        assertEquals("101010", decRes.get("binary"));
        assertEquals("*", decRes.get("ascii"));
        assertNotNull(decRes.get("ieee754_single"));

        // Hex 0x41424344 -> ASCII ABCD
        Map<String, Object> hexRes = cryptoEngineService.convertNumber("0x41424344", "hex");
        assertEquals("1094861636", hexRes.get("decimal"));
        assertEquals("ABCD", hexRes.get("ascii"));

        // Float 3.1415927 -> IEEE-754 Hex 0x40490FDB
        Map<String, Object> floatRes = cryptoEngineService.convertNumber("3.1415927", "float");
        assertEquals("0x40490FDB", floatRes.get("hex"));
        @SuppressWarnings("unchecked")
        Map<String, Object> single = (Map<String, Object>) floatRes.get("ieee754_single");
        assertNotNull(single);
        assertEquals("0x40490FDB", single.get("hex"));
    }

    @Test
    void testRsaHelperCalculationAndDecryption() {
        // p = 61, q = 53, e = 17 -> N = 3233, phi = 3120, d = 2753
        // If m = 65 ('A'), c = 65^17 mod 3233 = 2790
        Map<String, Object> res = cryptoEngineService.computeRsa("61", "53", "17", "2790");
        assertEquals("3233", res.get("n"));
        assertEquals("3120", res.get("phi"));
        assertEquals("2753", res.get("d"));
        assertEquals(12, res.get("bitLength"));
        assertEquals("65", res.get("m"));
        assertEquals("A", res.get("mAscii"));

        // Test with hex input: p = 0x3D (61), q = 0x35 (53)
        Map<String, Object> hexInputRes = cryptoEngineService.computeRsa("0x3D", "0x35", "17", "2790");
        assertEquals("3233", hexInputRes.get("n"));
        assertEquals("2753", hexInputRes.get("d"));
        assertEquals("A", hexInputRes.get("mAscii"));
    }

    @Test
    void testAtbashCipher() {
        String input = "flag{atbash_cipher_1337}";
        Map<String, Object> enc = cryptoEngineService.atbash(input);
        String cipher = (String) enc.get("result");
        assertEquals("uozt{zgyzhs_xrksvi_1337}", cipher);

        // Symmetric check: applying Atbash again decrypts it
        Map<String, Object> dec = cryptoEngineService.atbash(cipher);
        assertEquals(input, dec.get("result"));
    }

    @Test
    void testRailFenceCipher() {
        String plain = "WEAREDISCOVEREDFLEEATONCE";
        // 3 rails, offset 0 -> Row 0: WECRLTE, Row 1: ERDSOEEFEAOC, Row 2: AIVDEN
        Map<String, Object> enc = cryptoEngineService.railFence(plain, 3, 0, "encrypt");
        String ct = (String) enc.get("result");
        assertEquals("WECRLTEERDSOEEFEAOCAIVDEN", ct);

        // Decrypt
        Map<String, Object> dec = cryptoEngineService.railFence(ct, 3, 0, "decrypt");
        assertEquals(plain, dec.get("result"));

        // Brute force rails
        Map<String, Object> brute = cryptoEngineService.railFence(ct, 0, 0, "brute");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> candidates = (List<Map<String, Object>>) brute.get("candidates");
        assertNotNull(candidates);
        assertFalse(candidates.isEmpty());
        // Verify 3 rails candidate has plain text
        boolean found = candidates.stream().anyMatch(c -> plain.equals(c.get("text")) && (int) c.get("rails") == 3);
        assertTrue(found);
    }

    @Test
    void testBaconianCipher() {
        String msg = "HELLO";

        // Full 26-letter variant
        Map<String, Object> encFull = cryptoEngineService.baconian(msg, "encode", "full", "A", "B");
        String ctFull = (String) encFull.get("result");
        // H=AABBB, E=AABAA, L=ABABB, L=ABABB, O=ABBBA
        assertEquals("AABBB AABAA ABABB ABABB ABBBA", ctFull);

        Map<String, Object> decFull = cryptoEngineService.baconian(ctFull, "decode", "full", "A", "B");
        assertEquals("HELLO", decFull.get("result"));

        // Binary 0/1 decoding: 00111 00100 01011 01011 01110
        String binCt = "0011100100010110101101110";
        Map<String, Object> decBin = cryptoEngineService.baconian(binCt, "decode", "full", "A", "B");
        assertEquals("HELLO", decBin.get("fullDecoded"));

        // Standard 24-letter variant (I/J)
        Map<String, Object> encStd = cryptoEngineService.baconian("JOY", "encode", "standard", "A", "B");
        Map<String, Object> decStd = cryptoEngineService.baconian((String) encStd.get("result"), "decode", "standard", "A", "B");
        // J maps to I/J in standard Baconian
        assertTrue(((String) decStd.get("result")).contains("I/J"));
    }

    @Test
    void testBitwiseCalculatorOperations() {
        // 8-bit: a = 0xAA (10101010), b = 0x55 (01010101)
        Map<String, Object> andRes = cryptoEngineService.bitwiseCalc("0xAA", "0x55", "AND", 8);
        assertEquals("0", andRes.get("unsignedDec"));
        assertEquals("0x00", andRes.get("hex"));

        Map<String, Object> orRes = cryptoEngineService.bitwiseCalc("0xAA", "0x55", "OR", 8);
        assertEquals("255", orRes.get("unsignedDec"));
        assertEquals("0xFF", orRes.get("hex"));

        Map<String, Object> rolRes = cryptoEngineService.bitwiseCalc("0xAA", "1", "ROL", 8);
        assertEquals("0x55", rolRes.get("hex"));

        Map<String, Object> rorRes = cryptoEngineService.bitwiseCalc("0xAA", "1", "ROR", 8);
        assertEquals("0x55", rorRes.get("hex"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> grid = (List<Map<String, Object>>) rolRes.get("bitGrid");
        assertNotNull(grid);
        assertEquals(8, grid.size());
    }

    @Test
    void testRsaAttackLabAttacks() {
        // 1. Wiener Attack
        Map<String, String> wienerParams = Map.of("n", "1520961493", "e", "1415994953");
        Map<String, Object> wienerRes = cryptoEngineService.rsaAttack("wiener", wienerParams);
        assertEquals("success", wienerRes.get("status"));
        assertEquals("29", wienerRes.get("d"));

        // 2. Fermat Factorization (Close primes 100019, 100003 -> n = 10002200057)
        Map<String, String> fermatParams = Map.of("n", "10002200057");
        Map<String, Object> fermatRes = cryptoEngineService.rsaAttack("fermat", fermatParams);
        assertEquals("success", fermatRes.get("status"));
        assertEquals("100019", fermatRes.get("p"));
        assertEquals("100003", fermatRes.get("q"));

        // 3. Hastad Broadcast Attack (e=3, m=42 -> '*')
        Map<String, String> hastadParams = Map.of(
                "e", "3",
                "moduli", "10007, 10009, 10037",
                "ciphertexts", "4039, 4025, 3829"
        );
        Map<String, Object> hastadRes = cryptoEngineService.rsaAttack("hastad", hastadParams);
        assertEquals("success", hastadRes.get("status"));
        assertEquals("42", hastadRes.get("m"));
        assertEquals("*", hastadRes.get("mAscii"));

        // 4. Common Modulus Attack (n=3233, e1=7, e2=11, c1=1317, c2=2811 -> m=65 'A')
        Map<String, String> cmParams = Map.of(
                "n", "3233",
                "e1", "7",
                "e2", "11",
                "c1", "1317",
                "c2", "2811"
        );
        Map<String, Object> cmRes = cryptoEngineService.rsaAttack("common_modulus", cmParams);
        assertEquals("success", cmRes.get("status"));
        assertEquals("65", cmRes.get("m"));
        assertEquals("A", cmRes.get("mAscii"));
    }

    @Test
    void testVigenereKeyedAndAutomatedCrack() {
        String plain = "CRYPTOISFUNWHENYOUKNOWHOWCIPHERSWORKANDVIGENEREISCLASSICANDPOPULARINCOMPETITIONSTHISFLAGISCTFSECRETANDCRYPTOGRAPHYISVERYINTERESTINGTOLEARN";
        String key = "LEMON";

        // Encrypt
        Map<String, Object> enc = cryptoEngineService.solveVigenere(plain, key, "encrypt");
        String ct = (String) enc.get("result");
        assertNotNull(ct);
        assertNotEquals(plain, ct);

        // Decrypt with key
        Map<String, Object> dec = cryptoEngineService.solveVigenere(ct, key, "decrypt");
        assertEquals(plain, dec.get("result"));

        // Auto crack without key
        Map<String, Object> crack = cryptoEngineService.solveVigenere(ct, "", "crack");
        assertNotNull(crack.get("candidates"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> cands = (List<Map<String, Object>>) crack.get("candidates");
        assertFalse(cands.isEmpty());
        // Verify key LEMON was recovered
        boolean recovered = cands.stream().anyMatch(c -> key.equals(c.get("key")) || plain.equals(c.get("decrypted")));
        assertTrue(recovered);
    }
}
