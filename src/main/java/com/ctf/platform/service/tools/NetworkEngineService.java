package com.ctf.platform.service.tools;

import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.*;

@Service
public class NetworkEngineService {

    /**
     * Comprehensive IPv4 and IPv6 Subnet & CIDR Calculator.
     */
    public Map<String, Object> calculateSubnet(String ipInput, Integer cidrInput) {
        Map<String, Object> response = new LinkedHashMap<>();

        if (ipInput == null || ipInput.trim().isEmpty()) {
            response.put("error", "Please provide a valid IP address or CIDR notation (e.g. 192.168.1.100/24)");
            return response;
        }

        String raw = ipInput.trim();
        String ipPart = raw;
        int cidr = (cidrInput != null) ? cidrInput : -1;

        if (raw.contains("/")) {
            String[] parts = raw.split("/", 2);
            ipPart = parts[0].trim();
            try {
                cidr = Integer.parseInt(parts[1].trim());
            } catch (NumberFormatException e) {
                response.put("error", "Invalid CIDR prefix in notation: " + parts[1]);
                return response;
            }
        }

        // Detect IPv4 vs IPv6
        if (ipPart.contains(":")) {
            return calculateIpv6Subnet(ipPart, cidr >= 0 ? cidr : 64);
        } else {
            return calculateIpv4Subnet(ipPart, cidr >= 0 ? cidr : 24);
        }
    }

    private Map<String, Object> calculateIpv4Subnet(String ipStr, int cidr) {
        Map<String, Object> result = new LinkedHashMap<>();

        if (cidr < 0 || cidr > 32) {
            result.put("error", "IPv4 CIDR prefix must be between 0 and 32 (received: " + cidr + ")");
            return result;
        }

        long ipLong;
        try {
            InetAddress addr = InetAddress.getByName(ipStr);
            if (!(addr instanceof Inet4Address)) {
                result.put("error", "Expected IPv4 address, but got different address type: " + ipStr);
                return result;
            }
            byte[] bytes = addr.getAddress();
            ipLong = ((bytes[0] & 0xFFL) << 24) |
                     ((bytes[1] & 0xFFL) << 16) |
                     ((bytes[2] & 0xFFL) << 8) |
                     (bytes[3] & 0xFFL);
        } catch (Exception e) {
            result.put("error", "Invalid IPv4 address format: " + ipStr);
            return result;
        }

        // Netmask & Wildcard
        long maskLong = (cidr == 0) ? 0L : ((0xFFFFFFFFL << (32 - cidr)) & 0xFFFFFFFFL);
        long wildcardLong = (~maskLong) & 0xFFFFFFFFL;

        // Network & Broadcast
        long networkLong = ipLong & maskLong;
        long broadcastLong = networkLong | wildcardLong;

        // Host calculations
        long totalHosts = (cidr == 0) ? 4294967296L : (1L << (32 - cidr));
        long usableHosts;
        long firstUsableLong;
        long lastUsableLong;

        if (cidr == 32) {
            usableHosts = 1;
            firstUsableLong = ipLong;
            lastUsableLong = ipLong;
        } else if (cidr == 31) {
            // RFC 3021 Point-to-Point Links
            usableHosts = 2;
            firstUsableLong = networkLong;
            lastUsableLong = broadcastLong;
        } else {
            usableHosts = Math.max(0, totalHosts - 2);
            firstUsableLong = networkLong + 1;
            lastUsableLong = broadcastLong - 1;
        }

        String ipCanonical = longToIpv4(ipLong);
        String netmaskStr = longToIpv4(maskLong);
        String wildcardStr = longToIpv4(wildcardLong);
        String networkStr = longToIpv4(networkLong);
        String broadcastStr = longToIpv4(broadcastLong);
        String firstUsableStr = longToIpv4(firstUsableLong);
        String lastUsableStr = longToIpv4(lastUsableLong);

        result.put("version", "IPv4");
        result.put("ip", ipCanonical);
        result.put("cidr", cidr);
        result.put("cidrNotation", networkStr + "/" + cidr);
        result.put("netmask", netmaskStr);
        result.put("wildcard", wildcardStr);
        result.put("networkAddress", networkStr);
        result.put("broadcastAddress", broadcastStr);
        result.put("firstUsable", firstUsableStr);
        result.put("lastUsable", lastUsableStr);
        result.put("usableHostRange", firstUsableStr + " - " + lastUsableStr);
        result.put("totalHosts", totalHosts);
        result.put("usableHosts", usableHosts);

        // Class & Scope
        result.put("ipClass", getIpv4Class(ipLong));
        result.put("ipType", getIpv4Scope(ipLong));

        // Hex & Integer conversions
        result.put("ipInteger", ipLong);
        result.put("ipHex", "0x" + String.format("%08X", ipLong));
        result.put("netmaskHex", "0x" + String.format("%08X", maskLong));

        // Binary Representations
        result.put("binaryIp", toBinaryDottedString(ipLong));
        result.put("binaryNetmask", toBinaryDottedString(maskLong));
        result.put("binaryNetwork", toBinaryDottedString(networkLong));
        result.put("binaryBroadcast", toBinaryDottedString(broadcastLong));

        // Subnet Division Preview (split current network into next two smaller subnets if cidr < 32)
        if (cidr < 32) {
            int subCidr = cidr + 1;
            long subMask = ((0xFFFFFFFFL << (32 - subCidr)) & 0xFFFFFFFFL);
            long subSize = 1L << (32 - subCidr);
            long sub1Net = networkLong;
            long sub2Net = networkLong + subSize;
            List<Map<String, String>> subnets = new ArrayList<>();
            subnets.add(Map.of("subnet", longToIpv4(sub1Net) + "/" + subCidr, "range", longToIpv4(sub1Net + 1) + " - " + longToIpv4(sub1Net + subSize - 2)));
            subnets.add(Map.of("subnet", longToIpv4(sub2Net) + "/" + subCidr, "range", longToIpv4(sub2Net + 1) + " - " + longToIpv4(sub2Net + subSize - 2)));
            result.put("splitSubnets", subnets);
        }

        return result;
    }

    private Map<String, Object> calculateIpv6Subnet(String ipStr, int cidr) {
        Map<String, Object> result = new LinkedHashMap<>();

        if (cidr < 0 || cidr > 128) {
            result.put("error", "IPv6 CIDR prefix must be between 0 and 128 (received: " + cidr + ")");
            return result;
        }

        try {
            InetAddress addr = InetAddress.getByName(ipStr);
            if (!(addr instanceof Inet6Address)) {
                result.put("error", "Invalid IPv6 address: " + ipStr);
                return result;
            }

            byte[] ipBytes = addr.getAddress();
            BigInteger ipBig = new BigInteger(1, ipBytes);

            // Compute Netmask BigInteger
            BigInteger maskBig = BigInteger.ZERO;
            for (int i = 0; i < 128; i++) {
                if (i < cidr) {
                    maskBig = maskBig.setBit(127 - i);
                }
            }

            BigInteger networkBig = ipBig.and(maskBig);
            byte[] netBytes = to16ByteArray(networkBig);
            InetAddress netAddr = InetAddress.getByAddress(netBytes);

            String compressedNet = compressIpv6(netBytes);
            String compressedInput = compressIpv6(ipBytes);

            // Total Addresses = 2^(128 - cidr)
            int hostBits = 128 - cidr;
            BigInteger totalAddresses = BigInteger.valueOf(2).pow(hostBits);

            result.put("version", "IPv6");
            result.put("ip", compressedInput);
            result.put("cidr", cidr);
            result.put("cidrNotation", compressedNet + "/" + cidr);
            result.put("networkAddress", compressedNet);
            result.put("prefixLength", "/" + cidr);
            result.put("totalHosts", totalAddresses.toString());
            result.put("usableHosts", totalAddresses.toString());
            result.put("ipType", getIpv6Scope((Inet6Address) addr));
            result.put("expandedIp", toExpandedIpv6(ipBytes));
            result.put("compressedIp", compressedInput);

            return result;
        } catch (Exception e) {
            result.put("error", "Invalid IPv6 address format: " + ipStr);
            return result;
        }
    }

    private static String longToIpv4(long val) {
        return ((val >> 24) & 0xFF) + "." +
               ((val >> 16) & 0xFF) + "." +
               ((val >> 8) & 0xFF) + "." +
               (val & 0xFF);
    }

    private static String toBinaryDottedString(long val) {
        return String.format("%8s", Long.toBinaryString((val >> 24) & 0xFF)).replace(' ', '0') + "." +
               String.format("%8s", Long.toBinaryString((val >> 16) & 0xFF)).replace(' ', '0') + "." +
               String.format("%8s", Long.toBinaryString((val >> 8) & 0xFF)).replace(' ', '0') + "." +
               String.format("%8s", Long.toBinaryString(val & 0xFF)).replace(' ', '0');
    }

    private static String getIpv4Class(long ip) {
        long firstOctet = (ip >> 24) & 0xFF;
        if (firstOctet < 128) return "Class A (Default /8)";
        if (firstOctet < 192) return "Class B (Default /16)";
        if (firstOctet < 224) return "Class C (Default /24)";
        if (firstOctet < 240) return "Class D (Multicast)";
        return "Class E (Experimental)";
    }

    private static String getIpv4Scope(long ip) {
        long o1 = (ip >> 24) & 0xFF;
        long o2 = (ip >> 16) & 0xFF;

        if (o1 == 10) return "Private (RFC 1918 - 10.0.0.0/8)";
        if (o1 == 172 && (o2 >= 16 && o2 <= 31)) return "Private (RFC 1918 - 172.16.0.0/12)";
        if (o1 == 192 && o2 == 168) return "Private (RFC 1918 - 192.168.0.0/16)";
        if (o1 == 127) return "Loopback (RFC 1122 - 127.0.0.0/8)";
        if (o1 == 169 && o2 == 254) return "Link-Local / APIPA (RFC 3927)";
        if (o1 >= 224 && o1 <= 239) return "Multicast (RFC 5771)";
        if (o1 >= 240) return "Reserved / Experimental";
        if (o1 == 0) return "Current Network / This Host (0.0.0.0/8)";
        return "Public Internet";
    }

    private static String getIpv6Scope(Inet6Address addr) {
        if (addr.isLoopbackAddress()) return "Loopback (::1/128)";
        if (addr.isLinkLocalAddress()) return "Link-Local (fe80::/10)";
        if (addr.isMulticastAddress()) return "Multicast (ff00::/8)";
        if (addr.isSiteLocalAddress()) return "Unique Local (fc00::/7)";
        return "Global Unicast";
    }

    private static byte[] to16ByteArray(BigInteger bi) {
        byte[] arr = bi.toByteArray();
        byte[] res = new byte[16];
        if (arr.length <= 16) {
            System.arraycopy(arr, 0, res, 16 - arr.length, arr.length);
        } else {
            System.arraycopy(arr, arr.length - 16, res, 0, 16);
        }
        return res;
    }

    private static String compressIpv6(byte[] bytes) {
        int[] hextets = new int[8];
        for (int i = 0; i < 8; i++) {
            hextets[i] = ((bytes[i * 2] & 0xFF) << 8) | (bytes[i * 2 + 1] & 0xFF);
        }

        // Find longest sequence of zeroes >= 2
        int maxZeroLen = 0;
        int maxZeroStart = -1;
        int currZeroLen = 0;
        int currZeroStart = -1;

        for (int i = 0; i < 8; i++) {
            if (hextets[i] == 0) {
                if (currZeroStart == -1) {
                    currZeroStart = i;
                    currZeroLen = 1;
                } else {
                    currZeroLen++;
                }
            } else {
                if (currZeroLen > maxZeroLen) {
                    maxZeroLen = currZeroLen;
                    maxZeroStart = currZeroStart;
                }
                currZeroStart = -1;
                currZeroLen = 0;
            }
        }
        if (currZeroLen > maxZeroLen) {
            maxZeroLen = currZeroLen;
            maxZeroStart = currZeroStart;
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (maxZeroLen >= 2 && i == maxZeroStart) {
                sb.append("::");
                i += maxZeroLen - 1;
                continue;
            }
            if (sb.length() > 0 && !sb.toString().endsWith("::")) {
                sb.append(":");
            }
            sb.append(Integer.toHexString(hextets[i]));
        }
        return sb.toString();
    }

    private static String toExpandedIpv6(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x%02x", bytes[i] & 0xFF, bytes[i + 1] & 0xFF));
        }
        return sb.toString();
    }
}
