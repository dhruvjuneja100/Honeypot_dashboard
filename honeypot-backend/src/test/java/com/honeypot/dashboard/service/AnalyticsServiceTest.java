package com.honeypot.dashboard.service;

import com.honeypot.dashboard.repository.AttackLogRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class AnalyticsServiceTest {

    @Mock
    private AttackLogRepository attackLogRepository;

    @InjectMocks
    private AnalyticsService analyticsService;

    @Test
    public void testGetAttacksByType() {
        List<Object[]> mockData = Collections.singletonList(
                new Object[]{"SQL Injection", 5L}
        );
        when(attackLogRepository.countAttacksByType()).thenReturn(mockData);

        List<Map<String, Object>> result = analyticsService.getAttacksByType();
        assertEquals(1, result.size());
        assertEquals("SQL Injection", result.get(0).get("type"));
        assertEquals(5L, result.get(0).get("count"));
    }

    @Test
    public void testGetTopIps() {
        List<Object[]> mockData = Collections.singletonList(
                new Object[]{"192.168.1.100", 50L}
        );
        when(attackLogRepository.findTop10Ips()).thenReturn(mockData);

        List<Map<String, Object>> result = analyticsService.getTopIps();
        assertEquals(1, result.size());
        assertEquals("192.168.1.100", result.get(0).get("ip"));
        assertEquals(50L, result.get(0).get("count"));
    }

    @Test
    public void testGetGeoDistribution() {
        List<Object[]> mockData = Collections.singletonList(
                new Object[]{"US", "New York", 15L}
        );
        when(attackLogRepository.countGeoDistribution()).thenReturn(mockData);

        List<Map<String, Object>> result = analyticsService.getGeoDistribution();
        assertEquals(1, result.size());
        assertEquals("US", result.get(0).get("country"));
        assertEquals("New York", result.get(0).get("city"));
        assertEquals(15L, result.get(0).get("count"));
    }
}
