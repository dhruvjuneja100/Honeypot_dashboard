package com.honeypot.dashboard.interceptor;

import com.honeypot.dashboard.model.AttackLog;
import com.honeypot.dashboard.service.DetectionService;
import com.honeypot.dashboard.service.LoggingService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.LocalDateTime;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class HoneypotInterceptor implements HandlerInterceptor {

    @Autowired
    private DetectionService detectionService;

    @Autowired
    private LoggingService loggingService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        AttackLog log = new AttackLog();
        log.setTimestamp(LocalDateTime.now());
        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isEmpty()) {
            ipAddress = request.getRemoteAddr();
        } else {
            // X-Forwarded-For can contain multiple IPs, take the first one
            ipAddress = ipAddress.split(",")[0].trim();
        }
        log.setIpAddress(ipAddress);
        log.setEndpoint(request.getRequestURI());
        log.setHttpMethod(request.getMethod());

        // Extract Headers
        Map<String, String> headersMap = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                headersMap.put(headerName, request.getHeader(headerName));
            }
        }
        log.setHeaders(headersMap.toString());

        // Extract Payload (Query Params for GET, or basic parsing for POST)
        String payload = "";
        if (request instanceof org.springframework.web.multipart.MultipartHttpServletRequest) {
            org.springframework.web.multipart.MultipartHttpServletRequest multiReq = (org.springframework.web.multipart.MultipartHttpServletRequest) request;
            StringBuilder sb = new StringBuilder();
            multiReq.getFileMap().forEach((k, v) -> {
                sb.append("file=").append(v.getOriginalFilename()).append("&");
            });
            payload = sb.toString();
        }

        if (!request.getParameterMap().isEmpty()) {
            String paramPayload = request.getParameterMap().entrySet().stream()
                    .map(entry -> entry.getKey() + "=" + String.join(",", entry.getValue()))
                    .collect(Collectors.joining("&"));
            if (payload.isEmpty()) {
                payload = paramPayload;
            } else {
                payload += paramPayload;
            }
        }
        
        if (payload.isEmpty()) {
            try {
                payload = request.getReader().lines().collect(Collectors.joining("\n"));
            } catch (Exception e) {
                // Ignore
            }
        }
        log.setPayload(payload);

        // Classify the attack
        String attackType = detectionService.classifyAttack(log.getIpAddress(), log.getEndpoint(), log.getPayload());
        log.setAttackType(attackType);

        // Async save
        loggingService.saveAttackLog(log);

        return true;
    }
}
