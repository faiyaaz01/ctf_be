package com.ctf.platform.service.tools;

import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    // ── 2. OSINT INTELLIGENCE AGGREGATOR & QUERY ENGINE ─────────────────
    private static final Pattern CRT_SH_NAME_PATTERN = Pattern.compile("\"name_value\"\\s*:\\s*\"([^\"]+)\"");

    public Map<String, Object> generateOsintQueries(String rawInput, String forcedType, boolean queryCrtSh) {
        Map<String, Object> response = new LinkedHashMap<>();

        if (rawInput == null || rawInput.trim().isEmpty()) {
            response.put("error", "Target cannot be empty. Please enter a Domain, IP, Hash, Email, or Username.");
            return response;
        }

        String target = rawInput.trim();
        // Remove protocol if present
        if (target.startsWith("http://")) target = target.substring(7);
        if (target.startsWith("https://")) target = target.substring(8);
        // Remove trailing paths / slashes if it looks like a domain or host
        if (target.contains("/") && !target.contains(" ")) {
            target = target.split("/")[0];
        }

        String detectedType = (forcedType != null && !forcedType.equalsIgnoreCase("auto"))
                ? forcedType.toLowerCase()
                : detectTargetType(target);

        response.put("target", target);
        response.put("detectedType", detectedType);

        List<Map<String, Object>> platforms = new ArrayList<>();
        List<Map<String, String>> dorks = new ArrayList<>();
        List<String> subdomains = new ArrayList<>();

        String encodedTarget = urlEncode(target);

        switch (detectedType) {
            case "domain":
                platforms.addAll(buildDomainPlatforms(target, encodedTarget));
                dorks.addAll(buildDomainDorks(target, encodedTarget));
                if (queryCrtSh) {
                    subdomains.addAll(fetchCrtShSubdomains(target));
                }
                break;
            case "ip":
            case "ipv6":
                platforms.addAll(buildIpPlatforms(target, encodedTarget));
                break;
            case "hash_md5":
            case "hash_sha1":
            case "hash_sha256":
            case "hash":
                platforms.addAll(buildHashPlatforms(target, encodedTarget));
                break;
            case "email":
                platforms.addAll(buildEmailPlatforms(target, encodedTarget));
                break;
            case "username":
            default:
                platforms.addAll(buildUsernamePlatforms(target, encodedTarget));
                break;
        }

        response.put("platforms", platforms);
        response.put("dorks", dorks);
        response.put("subdomains", subdomains);
        response.put("subdomainsCount", subdomains.size());

        return response;
    }

    public List<String> fetchCrtShSubdomains(String domain) {
        Set<String> uniqueSubdomains = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://crt.sh/?q=%25." + domain + "&output=json"))
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CTF-Platform-OSINT/1.0")
                    .GET()
                    .build();

            HttpResponse<String> resp = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200 && resp.body() != null && !resp.body().trim().isEmpty()) {
                Matcher matcher = CRT_SH_NAME_PATTERN.matcher(resp.body());
                while (matcher.find()) {
                    String rawNames = matcher.group(1).replace("\\n", "\n").replace("\\r", "");
                    for (String n : rawNames.split("\n")) {
                        String clean = n.trim().toLowerCase();
                        if (clean.startsWith("*.")) clean = clean.substring(2);
                        if (clean.endsWith("." + domain) || clean.equals(domain)) {
                            uniqueSubdomains.add(clean);
                        }
                    }
                }
            }
        } catch (Exception ignored) {
            // crt.sh can be busy or rate-limited; fallback gracefully
        }
        return new ArrayList<>(uniqueSubdomains);
    }

    private String detectTargetType(String t) {
        if (t.matches("^(\\d{1,3}\\.){3}\\d{1,3}$")) return "ip";
        if (t.contains(":") && t.matches("^[0-9a-fA-F:]+$")) return "ipv6";
        if (t.matches("^[a-fA-F0-9]{32}$")) return "hash_md5";
        if (t.matches("^[a-fA-F0-9]{40}$")) return "hash_sha1";
        if (t.matches("^[a-fA-F0-9]{64}$")) return "hash_sha256";
        if (t.contains("@") && t.matches("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) return "email";
        if (t.contains(".") && t.matches("^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$")) return "domain";
        return "username";
    }

    private List<Map<String, Object>> buildDomainPlatforms(String target, String enc) {
        List<Map<String, Object>> list = new ArrayList<>();
        list.add(platformItem("Shodan", "Infrastructure & Open Ports", "hostname:\"" + target + "\"", "https://www.shodan.io/search?query=hostname%3A%22" + enc + "%22", "Network"));
        list.add(platformItem("Censys", "TLS Certs & Exposed Services", "services.tls.certificates.leaf_data.names: " + target, "https://search.censys.io/search?q=services.tls.certificates.leaf_data.names%3A+" + enc, "Network"));
        list.add(platformItem("VirusTotal", "Reputation & Malware Intel", target, "https://www.virustotal.com/gui/domain/" + target, "Threat Intel"));
        list.add(platformItem("crt.sh", "Certificate Transparency Logs", "%." + target, "https://crt.sh/?q=%25." + enc, "Certificates"));
        list.add(platformItem("URLScan.io", "DOM Scanner & Screenshots", "page.domain:" + target, "https://urlscan.io/search/#page.domain%3A" + enc, "Web Recon"));
        list.add(platformItem("AlienVault OTX", "Threat Pulses & Indicators", target, "https://otx.alienvault.com/indicator/domain/" + target, "Threat Intel"));
        list.add(platformItem("SecurityTrails", "Historic DNS & Subdomains", target, "https://securitytrails.com/domain/" + target + "/dns", "DNS Recon"));
        list.add(platformItem("Wayback Machine", "Historic Archived Pages", target, "https://web.archive.org/web/*/" + target + "/*", "Archives"));
        list.add(platformItem("DNSDumpster", "DNS Map & Subdomain Discovery", target, "https://dnsdumpster.com/", "DNS Recon"));
        list.add(platformItem("Hunter.io", "Corporate Email Patterns", target, "https://hunter.io/try/search/" + target, "Identity"));
        return list;
    }

    private List<Map<String, Object>> buildIpPlatforms(String target, String enc) {
        List<Map<String, Object>> list = new ArrayList<>();
        list.add(platformItem("Shodan", "Host Profile & Exposed Ports", target, "https://www.shodan.io/host/" + target, "Network"));
        list.add(platformItem("Censys", "Host Services & Protocols", target, "https://search.censys.io/hosts/" + target, "Network"));
        list.add(platformItem("VirusTotal", "IP Reputation & Malicious Detections", target, "https://www.virustotal.com/gui/ip-address/" + target, "Threat Intel"));
        list.add(platformItem("AbuseIPDB", "Abuse & Brute Force Reports", target, "https://www.abuseipdb.com/check/" + target, "Threat Intel"));
        list.add(platformItem("AlienVault OTX", "Threat Intel & Related Pulses", target, "https://otx.alienvault.com/indicator/ip/" + target, "Threat Intel"));
        list.add(platformItem("IPinfo.io", "Geolocation, ASN & Org", target, "https://ipinfo.io/" + target, "Geo / ASN"));
        list.add(platformItem("BGP He.net", "Routing, Prefix & AS Info", target, "https://bgp.he.net/ip/" + target, "BGP / Routing"));
        list.add(platformItem("URLScan.io", "Observed Web Scans on IP", "page.ip:" + target, "https://urlscan.io/search/#page.ip%3A" + enc, "Web Recon"));
        return list;
    }

    private List<Map<String, Object>> buildHashPlatforms(String target, String enc) {
        List<Map<String, Object>> list = new ArrayList<>();
        list.add(platformItem("VirusTotal", "Multi-Engine Malware Analysis", target, "https://www.virustotal.com/gui/file/" + target, "Malware"));
        list.add(platformItem("MalwareBazaar", "Public Malware Sample Database", target, "https://bazaar.abuse.ch/sample/" + target + "/", "Malware"));
        list.add(platformItem("Hybrid Analysis", "Free Sandbox Analysis", target, "https://www.hybrid-analysis.com/search?query=" + target, "Sandbox"));
        list.add(platformItem("Any.Run", "Interactive Malware Sandbox", target, "https://app.any.run/submissions/#search=" + target, "Sandbox"));
        list.add(platformItem("Hashmob", "Hash Lookup & Rainbow Cracker", target, "https://hashmob.net/search", "Cracking"));
        list.add(platformItem("CrackStation", "Wordlist Lookup for MD5/SHA1", target, "https://crackstation.net/", "Cracking"));
        return list;
    }

    private List<Map<String, Object>> buildEmailPlatforms(String target, String enc) {
        List<Map<String, Object>> list = new ArrayList<>();
        String domainPart = target.contains("@") ? target.split("@")[1] : target;
        list.add(platformItem("Hunter.io", "Domain Email Finder", domainPart, "https://hunter.io/try/search/" + domainPart, "Identity"));
        list.add(platformItem("HaveIBeenPwned", "Data Breach Database", target, "https://haveibeenpwned.com/", "Breach Check"));
        list.add(platformItem("IntelX", "Intelligence X Search Engine", target, "https://intelx.io/?s=" + enc, "Intel / Leaks"));
        list.add(platformItem("EmailRep.io", "Reputation & Malicious Scoring", target, "https://emailrep.io/" + target, "Reputation"));
        list.add(platformItem("Google Search", "Exact Email Appearances", "\"" + target + "\"", "https://www.google.com/search?q=%22" + enc + "%22", "Dork"));
        return list;
    }

    private List<Map<String, Object>> buildUsernamePlatforms(String target, String enc) {
        List<Map<String, Object>> list = new ArrayList<>();
        list.add(platformItem("GitHub", "Source Code & User Profile", target, "https://github.com/" + target, "Code / Dev"));
        list.add(platformItem("WhatsMyName / Namechk", "300+ Social Media Platforms", target, "https://whatsmyname.app/", "Social"));
        list.add(platformItem("X (Twitter)", "Social Media Profile", target, "https://x.com/" + target, "Social"));
        list.add(platformItem("Reddit", "Reddit User Submissions", target, "https://www.reddit.com/user/" + target, "Social"));
        list.add(platformItem("Google Dork", "Exact Username Mentions", "\"" + target + "\"", "https://www.google.com/search?q=%22" + enc + "%22", "Search"));
        return list;
    }

    private List<Map<String, String>> buildDomainDorks(String target, String enc) {
        List<Map<String, String>> dorks = new ArrayList<>();
        dorks.add(Map.of(
                "title", "Config & Environment Files",
                "dork", "site:" + target + " ext:env OR ext:yml OR ext:yaml OR ext:json OR ext:conf OR ext:ini",
                "url", "https://www.google.com/search?q=site%3A" + enc + "+(ext%3Aenv+OR+ext%3Ayml+OR+ext%3Ayaml+OR+ext%3Ajson+OR+ext%3Aconf+OR+ext%3Aini)"
        ));
        dorks.add(Map.of(
                "title", "Database & Backup Dumps",
                "dork", "site:" + target + " ext:sql OR ext:db OR ext:mdb OR ext:bak OR ext:dump OR ext:tar OR ext:zip",
                "url", "https://www.google.com/search?q=site%3A" + enc + "+(ext%3Asql+OR+ext%3Adb+OR+ext%3Amdb+OR+ext%3Abak+OR+ext%3Adump+OR+ext%3Azip)"
        ));
        dorks.add(Map.of(
                "title", "Admin & Login Portals",
                "dork", "site:" + target + " inurl:admin OR inurl:login OR inurl:portal OR inurl:cpanel OR inurl:dashboard",
                "url", "https://www.google.com/search?q=site%3A" + enc + "+(inurl%3Aadmin+OR+inurl%3Alogin+OR+inurl%3Aportal+OR+inurl%3Acpanel)"
        ));
        dorks.add(Map.of(
                "title", "Directory Traversal / Index Of",
                "dork", "site:" + target + " intitle:\"index of\" OR intitle:\"index.of\"",
                "url", "https://www.google.com/search?q=site%3A" + enc + "+(intitle%3A%22index+of%22+OR+intitle%3A%22index.of%22)"
        ));
        dorks.add(Map.of(
                "title", "Sensitive Documents (PDF / Office)",
                "dork", "site:" + target + " filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:pptx",
                "url", "https://www.google.com/search?q=site%3A" + enc + "+(filetype%3Apdf+OR+filetype%3Adocx+OR+filetype%3Axlsx)"
        ));
        dorks.add(Map.of(
                "title", "WordPress & CMS Directories",
                "dork", "site:" + target + " inurl:wp-content OR inurl:wp-includes OR inurl:wp-json",
                "url", "https://www.google.com/search?q=site%3A" + enc + "+(inurl%3Awp-content+OR+inurl%3Awp-includes+OR+inurl%3Awp-json)"
        ));
        return dorks;
    }

    private Map<String, Object> platformItem(String provider, String desc, String query, String url, String category) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("provider", provider);
        map.put("description", desc);
        map.put("query", query);
        map.put("url", url);
        map.put("category", category);
        return map;
    }

    private static String urlEncode(String val) {
        return URLEncoder.encode(val, StandardCharsets.UTF_8);
    }
}
