package com.honeypot.dashboard.service;

import com.honeypot.dashboard.repository.AttackLogRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class DetectionServiceTest {

    @Mock
    private AttackLogRepository attackLogRepository;

    @InjectMocks
    private DetectionService detectionService;

    @Test
    public void testSqlInjectionDetection() {
        String payload = "username=admin' OR 1=1 --";
        String result = detectionService.classifyAttack("127.0.0.1", "/login", payload);
        assertEquals("SQL_INJECTION", result);
    }

    @Test
    public void testXssDetection() {
        String payload = "q=<script>alert('xss')</script>";
        String result = detectionService.classifyAttack("127.0.0.1", "/api/data", payload);
        assertEquals("XSS", result);
    }

    @Test
    public void testPathTraversalDetection() {
        String payload = "file=../../../etc/passwd";
        String result = detectionService.classifyAttack("127.0.0.1", "/api/data", payload);
        assertEquals("PATH_TRAVERSAL", result);
    }

    @Test
    public void testMaliciousUploadDetection() {
        String payload = "filename=shell.php";
        String result = detectionService.classifyAttack("127.0.0.1", "/upload", payload);
        assertEquals("MALICIOUS_UPLOAD", result);
    }

    @Test
    public void testBruteForceDetection() {
        when(attackLogRepository.countByIpAddressAndEndpointAndTimestampAfter(eq("192.168.1.100"), eq("/login"), any(LocalDateTime.class)))
                .thenReturn(15);
        
        String result = detectionService.classifyAttack("192.168.1.100", "/login", "user=test");
        assertEquals("BRUTE_FORCE", result);
    }

    @Test
    public void testUnknownDetection() {
        String result = detectionService.classifyAttack("10.0.0.1", "/api/data", "param=value");
        assertEquals("UNKNOWN", result);
    }
}
