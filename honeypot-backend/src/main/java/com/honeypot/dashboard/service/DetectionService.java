package com.honeypot.dashboard.service;

import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@Service
public class DetectionService {

    // SQL Injection: covers SELECT/DROP/INSERT/UPDATE/UNION and quote-based bypass tricks
    private static final Pattern SQLI_PATTERN = Pattern.compile(
        "(?i)(SELECT\\s+.+\\s+FROM|DROP\\s+TABLE|INSERT\\s+INTO|UPDATE\\s+.+\\s+SET" +
        "|DELETE\\s+FROM|UNION\\s+(ALL\\s+)?SELECT|EXEC(UTE)?\\s*\\(" +
        "|['\"]\\s*(OR|AND)\\s*['\"]?\\d*['\"]?\\s*=\\s*['\"]?\\d*" +
        "|['\"]\\s*--\\s*|['\"]\\s*#\\s*|['\"]\\s*;\\s*DROP)"
    );

    // XSS: covers <script> with or without closing tag, common event handlers, javascript: URIs
    private static final Pattern XSS_PATTERN = Pattern.compile(
        "(?i)(<script[^>]*>|<\\/script>" +
        "|on(error|load|click|mouseover|mouseout|focus|blur|change|submit|keydown|keyup|keypress)\\s*=" +
        "|javascript:\\s*\\w" +
        "|alert\\s*\\(|prompt\\s*\\(|confirm\\s*\\(" +
        "|<iframe|document\\.(cookie|write|location)|window\\.location)"
    );

    // Path Traversal: covers ../, ..\, URL-encoded variants, and sensitive file paths
    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile(
        "(?i)(\\.\\.\\/|\\.\\.\\\\|%2e%2e%2f|%2e%2e%5c|%252e%252e" +
        "|\\/etc\\/(passwd|shadow|hosts|group)" +
        "|\\/windows\\/(win\\.ini|system32)" +
        "|\\.\\.\\.\\.|%c0%af)"
    );

    // Malicious Upload: matches dangerous extensions as a filename= parameter value
    private static final Pattern MALICIOUS_UPLOAD_PATTERN = Pattern.compile(
        "(?i)\\.(exe|sh|php[0-9]?|phtml|phar|asp|aspx|jsp|py|rb|pl|vbs|bat|cmd|ps1|jar|war)(?:[&\\s]|$)"
    );

    // Command Injection: common shell commands typed into the /debug console
    private static final Pattern COMMAND_INJECTION_PATTERN = Pattern.compile(
        "(?i)(;\\s*\\w+|&&\\s*\\w+|\\|\\s*\\w+|\\$\\([^)]*\\)|`[^`]+`" +
        "|\\b(cat|ls|pwd|id|whoami|wget|curl|nc|bash|sh|cmd|powershell" +
        "|python|perl|ruby|php|rm\\s+-rf|chmod|chown|ifconfig|netstat|nmap|ping|traceroute|uname)\\b)"
    );

    // Brute Force tracking: keyed by "ipAddress:endpoint" for per-endpoint isolation
    private final Map<String, List<LocalDateTime>> loginAttempts = new ConcurrentHashMap<>();

    public String classifyAttack(String ipAddress, String endpoint, String payload) {
        List<String> attackTypes = new ArrayList<>();

        // --- 1. Brute Force Detection (per IP + endpoint combination) ---
        if (endpoint != null && (endpoint.contains("/login") || endpoint.contains("/admin"))) {
            String key = (ipAddress != null ? ipAddress : "unknown") + ":" + endpoint;
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime fiveMinutesAgo = now.minusMinutes(5);

            loginAttempts.putIfAbsent(key, new ArrayList<>());
            List<LocalDateTime> attempts = loginAttempts.get(key);
            synchronized (attempts) {
                attempts.removeIf(time -> time.isBefore(fiveMinutesAgo));
                attempts.add(now);
                if (attempts.size() > 10) {
                    attackTypes.add("BRUTE_FORCE");
                }
            }
        }

        // --- 2. Payload-based pattern matching ---
        if (payload != null && !payload.isEmpty()) {
            if (SQLI_PATTERN.matcher(payload).find()) {
                attackTypes.add("SQL_INJECTION");
            }
            if (XSS_PATTERN.matcher(payload).find()) {
                attackTypes.add("XSS");
            }
            if (PATH_TRAVERSAL_PATTERN.matcher(payload).find()) {
                attackTypes.add("PATH_TRAVERSAL");
            }
            if (COMMAND_INJECTION_PATTERN.matcher(payload).find()) {
                attackTypes.add("COMMAND_INJECTION");
            }
        }

        // --- 3. Endpoint-based detection ---
        if (endpoint != null) {
            if (PATH_TRAVERSAL_PATTERN.matcher(endpoint).find()) {
                if (!attackTypes.contains("PATH_TRAVERSAL")) {
                    attackTypes.add("PATH_TRAVERSAL");
                }
            }
            if (endpoint.contains("/upload") && payload != null && !payload.isEmpty()
                    && MALICIOUS_UPLOAD_PATTERN.matcher(payload).find()) {
                attackTypes.add("MALICIOUS_UPLOAD");
            }
        }

        return attackTypes.isEmpty() ? "UNKNOWN" : String.join(", ", attackTypes);
    }
}
