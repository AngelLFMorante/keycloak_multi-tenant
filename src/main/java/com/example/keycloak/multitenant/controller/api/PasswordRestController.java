package com.example.keycloak.multitenant.controller.api;

import com.example.keycloak.multitenant.service.PasswordFlowService;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/{realm}/password")
public class PasswordRestController {

    private final PasswordFlowService flow;

    public PasswordRestController(PasswordFlowService flow) {
        this.flow = flow;
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verify(@PathVariable String realm,
                                    @RequestParam String token) {
        flow.verifyEmail(realm, token);
        return ResponseEntity.ok(Map.of("message", "Email verificado"));
    }

    @PostMapping("/set")
    public ResponseEntity<?> setPassword(@PathVariable String realm,
                                         @RequestParam String token,
                                         @RequestParam String password) {
        flow.setPassword(realm, token, password);
        return ResponseEntity.ok(Map.of("message", "Contraseña establecida"));
    }
}
