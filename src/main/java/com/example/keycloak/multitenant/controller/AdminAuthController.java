package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.service.AdminAuthService;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminAuthController {

    private final AdminAuthService adminAuthService;

    public AdminAuthController(AdminAuthService adminAuthService) {
        this.adminAuthService = adminAuthService;
    }

    @PostMapping("/token")
    public ResponseEntity<AccessTokenResponse> getAdminToken() {
        AccessTokenResponse tokenResponse = adminAuthService.loginAsAdmin();
        return ResponseEntity.ok(tokenResponse);
    }
}
