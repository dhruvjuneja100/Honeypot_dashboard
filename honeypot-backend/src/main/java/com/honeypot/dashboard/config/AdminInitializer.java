package com.honeypot.dashboard.config;

import com.honeypot.dashboard.model.AdminUser;
import com.honeypot.dashboard.repository.AdminUserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AdminInitializer {

    @Bean
    public CommandLineRunner initAdminUser(AdminUserRepository adminUserRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            // Credentials are set via environment variables in production.
            // Locally they fall back to admin / admin123.
            String username = System.getenv().getOrDefault("ADMIN_USER", "admin");
            String password = System.getenv().getOrDefault("ADMIN_PASS", "admin123");

            if (adminUserRepository.findByUsername(username).isEmpty()) {
                AdminUser admin = new AdminUser();
                admin.setUsername(username);
                admin.setPassword(passwordEncoder.encode(password));
                adminUserRepository.save(admin);
                System.out.println("Admin user created: " + username);
            }
        };
    }
}
