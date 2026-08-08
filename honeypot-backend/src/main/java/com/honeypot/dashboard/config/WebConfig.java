package com.honeypot.dashboard.config;

import com.honeypot.dashboard.interceptor.HoneypotInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private HoneypotInterceptor honeypotInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // Register the interceptor to intercept all requests to our fake endpoints
        registry.addInterceptor(honeypotInterceptor)
                .addPathPatterns("/login", "/api/data", "/upload", "/admin", "/debug", "/backup");
    }
}
