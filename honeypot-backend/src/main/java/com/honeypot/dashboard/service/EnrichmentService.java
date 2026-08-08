package com.honeypot.dashboard.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class EnrichmentService {

    private final RestTemplate restTemplate = new RestTemplate();
    private final Map<String, EnrichedIpData> cache = new ConcurrentHashMap<>();
    
    // In a real scenario, this would be in application.properties
    private static final String ABUSE_IP_DB_KEY = "dummy-api-key";

    public static class EnrichedIpData {
        public String country;
        public String city;
        public Double latitude;
        public Double longitude;
        public Integer threatScore;
    }

    public EnrichedIpData enrichIp(String ipAddress) {
        // Handle localhost/private IPs gracefully
        if (ipAddress.startsWith("127.") || ipAddress.startsWith("192.168.") || ipAddress.startsWith("10.") || ipAddress.equals("0:0:0:0:0:0:0:1")) {
            EnrichedIpData data = new EnrichedIpData();
            data.country = "Local Network (Internal)";
            data.city = "Local Network (Internal)";
            data.latitude = 0.0;
            data.longitude = 0.0;
            data.threatScore = 0;
            return data;
        }

        return cache.computeIfAbsent(ipAddress, this::fetchFromApis);
    }

    private EnrichedIpData fetchFromApis(String ip) {
        EnrichedIpData data = new EnrichedIpData();
        
        // 1. GeoIP Integration (ip-api.com)
        try {
            String geoUrl = "http://ip-api.com/json/" + ip;
            ResponseEntity<Map> geoResponse = restTemplate.getForEntity(geoUrl, Map.class);
            if (geoResponse.getStatusCode().is2xxSuccessful() && geoResponse.getBody() != null) {
                Map<String, Object> body = geoResponse.getBody();
                if ("success".equals(body.get("status"))) {
                    data.country = (String) body.get("country");
                    data.city = (String) body.get("city");
                    Object lat = body.get("lat");
                    Object lon = body.get("lon");
                    if (lat instanceof Number) data.latitude = ((Number) lat).doubleValue();
                    if (lon instanceof Number) data.longitude = ((Number) lon).doubleValue();
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to fetch GeoIP for " + ip + ": " + e.getMessage());
        }

        // 2. Threat Intel (Mocking AbuseIPDB API for now)
        try {
            // Uncomment to use real API:
            /*
            String threatUrl = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip;
            HttpHeaders headers = new HttpHeaders();
            headers.set("Key", ABUSE_IP_DB_KEY);
            headers.set("Accept", "application/json");
            HttpEntity<String> entity = new HttpEntity<>("", headers);
            ResponseEntity<Map> threatResponse = restTemplate.exchange(threatUrl, HttpMethod.GET, entity, Map.class);
            
            if (threatResponse.getStatusCode().is2xxSuccessful() && threatResponse.getBody() != null) {
                Map<String, Object> body = threatResponse.getBody();
                Map<String, Object> dataMap = (Map<String, Object>) body.get("data");
                Object score = dataMap.get("abuseConfidenceScore");
                if (score instanceof Number) data.threatScore = ((Number) score).intValue();
            }
            */
            
            // Mock threat score based on some IP characteristic for testing
            if (ip.startsWith("8.8.")) {
                data.threatScore = 0; // Google DNS is safe
            } else {
                data.threatScore = (ip.hashCode() % 100); // Random deterministic score for others
                if (data.threatScore < 0) data.threatScore *= -1;
            }
            
        } catch (Exception e) {
            System.err.println("Failed to fetch Threat Intel for " + ip + ": " + e.getMessage());
            data.threatScore = 0;
        }

        return data;
    }
}
