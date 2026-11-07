package com.ctf.platform;

import com.ctf.platform.service.tools.NetworkEngineService;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class NetworkEngineServiceTest {

    private final NetworkEngineService service = new NetworkEngineService();

    @Test
    void testStandardCidr24() {
        Map<String, Object> res = service.calculateSubnet("192.168.1.105/24", null);
        assertNull(res.get("error"));
        assertEquals("192.168.1.105", res.get("ip"));
        assertEquals(24, res.get("cidr"));
        assertEquals("255.255.255.0", res.get("netmask"));
        assertEquals("0.0.0.255", res.get("wildcard"));
        assertEquals("192.168.1.0", res.get("networkAddress"));
        assertEquals("192.168.1.255", res.get("broadcastAddress"));
        assertEquals("192.168.1.1", res.get("firstUsable"));
        assertEquals("192.168.1.254", res.get("lastUsable"));
        assertEquals(256L, res.get("totalHosts"));
        assertEquals(254L, res.get("usableHosts"));
        assertEquals("Class C (Default /24)", res.get("ipClass"));
        assertEquals("Private (RFC 1918 - 192.168.0.0/16)", res.get("ipType"));
    }

    @Test
    void testSingleHostCidr32() {
        Map<String, Object> res = service.calculateSubnet("8.8.8.8/32", null);
        assertNull(res.get("error"));
        assertEquals("8.8.8.8", res.get("networkAddress"));
        assertEquals("255.255.255.255", res.get("netmask"));
        assertEquals("0.0.0.0", res.get("wildcard"));
        assertEquals(1L, res.get("usableHosts"));
        assertEquals("Public Internet", res.get("ipType"));
    }

    @Test
    void testRfc3021Cidr31() {
        Map<String, Object> res = service.calculateSubnet("10.0.0.0/31", null);
        assertNull(res.get("error"));
        assertEquals(2L, res.get("usableHosts"));
        assertEquals("10.0.0.0", res.get("firstUsable"));
        assertEquals("10.0.0.1", res.get("lastUsable"));
    }

    @Test
    void testIpv6Calculation() {
        Map<String, Object> res = service.calculateSubnet("2001:db8::1/64", null);
        assertNull(res.get("error"));
        assertEquals("IPv6", res.get("version"));
        assertEquals(64, res.get("cidr"));
        assertEquals("2001:db8::/64", res.get("cidrNotation"));
        assertEquals("Global Unicast", res.get("ipType"));
    }

    @Test
    void testOsintDomainRecon() {
        Map<String, Object> res = service.generateOsintQueries("example.com", "auto", false);
        assertNull(res.get("error"));
        assertEquals("example.com", res.get("target"));
        assertEquals("domain", res.get("detectedType"));
        assertNotNull(res.get("platforms"));
        assertNotNull(res.get("dorks"));
    }

    @Test
    void testOsintIpRecon() {
        Map<String, Object> res = service.generateOsintQueries("1.1.1.1", "auto", false);
        assertNull(res.get("error"));
        assertEquals("1.1.1.1", res.get("target"));
        assertEquals("ip", res.get("detectedType"));
    }

    @Test
    void testOsintHashDetection() {
        Map<String, Object> res = service.generateOsintQueries("e4d909c290d0fb1ca068ffaddf22cbd0add8abff", "auto", false);
        assertNull(res.get("error"));
        assertEquals("hash_sha1", res.get("detectedType"));
    }
}
