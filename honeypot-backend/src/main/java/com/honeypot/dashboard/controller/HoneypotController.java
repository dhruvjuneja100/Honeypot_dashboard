package com.honeypot.dashboard.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.Map;

@RestController
public class HoneypotController {

    @GetMapping("/login")
    public void loginPage(jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
        response.sendRedirect("/login.html");
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> fakeLogin() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "error");
        response.put("message", "Invalid username or password");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @GetMapping("/api/data")
    public void searchDataPage(jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
        response.sendRedirect("/data.html");
    }

    @PostMapping("/api/data")
    public ResponseEntity<Map<String, Object>> fakeData() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "error");
        response.put("message", "Query execution failed");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    @GetMapping("/upload")
    public void uploadPage(jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
        response.sendRedirect("/upload.html");
    }

    @PostMapping("/upload")
    public ResponseEntity<Map<String, Object>> fakeUpload(@RequestParam(value = "file", required = false) MultipartFile file) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "error");
        response.put("message", "Upload directory not writable");
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    @GetMapping("/admin")
    public void adminPage(jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
        response.sendRedirect("/admin.html");
    }

    @PostMapping("/admin")
    public ResponseEntity<Map<String, Object>> fakeAdmin() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "error");
        response.put("message", "Access denied. Insufficient privileges.");
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    @GetMapping("/debug")
    public void debugPage(jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
        response.sendRedirect("/debug.html");
    }

    @PostMapping("/debug")
    public ResponseEntity<Map<String, Object>> fakeDebug() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "error");
        response.put("message", "command execution blocked");
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    @GetMapping("/backup")
    public void backupPage(jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
        response.sendRedirect("/backup.html");
    }

    @PostMapping("/backup")
    public ResponseEntity<Map<String, Object>> fakeBackup() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "error");
        response.put("message", "Backup file not found");
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }
}
