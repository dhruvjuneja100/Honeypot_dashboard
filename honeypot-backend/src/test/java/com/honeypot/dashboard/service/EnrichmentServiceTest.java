package com.honeypot.dashboard.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.*;

public class EnrichmentServiceTest {

    private EnrichmentService enrichmentService;

    @BeforeEach
    public void setup() {
        enrichmentService = new EnrichmentService();
    }

    @Test
    public void testLocalIpEnrichment() {
        EnrichmentService.EnrichedIpData data = enrichmentService.enrichIp("127.0.0.1");
        assertEquals("Local", data.country);
        assertEquals("Local", data.city);
        assertEquals(0.0, data.latitude);
        assertEquals(0.0, data.longitude);
        assertEquals(0, data.threatScore);
    }

    @Test
    public void testPublicIpEnrichment() {
        // We use Google's Public DNS IP for testing GeoIP integration
        // Note: This relies on internet access and ip-api.com being up
        EnrichmentService.EnrichedIpData data = enrichmentService.enrichIp("8.8.8.8");
        assertNotNull(data);
        assertEquals("United States", data.country);
        assertNotNull(data.latitude);
        assertNotNull(data.longitude);
        assertEquals(0, data.threatScore); // Our mock logic sets 8.8.x.x to 0
    }
    
    @Test
    public void testCaching() {
        long startTime1 = System.currentTimeMillis();
        EnrichmentService.EnrichedIpData data1 = enrichmentService.enrichIp("1.1.1.1");
        long duration1 = System.currentTimeMillis() - startTime1;

        long startTime2 = System.currentTimeMillis();
        EnrichmentService.EnrichedIpData data2 = enrichmentService.enrichIp("1.1.1.1");
        long duration2 = System.currentTimeMillis() - startTime2;

        // The second call should be extremely fast because it is cached
        assertTrue(duration2 <= duration1 || duration2 < 10);
        assertEquals(data1.country, data2.country);
    }
}
