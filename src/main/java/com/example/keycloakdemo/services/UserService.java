package com.example.keycloakdemo.services;

import com.example.keycloakdemo.models.AppUser;
import com.example.keycloakdemo.repositories.UserRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final KeycloakAdminService keycloakAdminService;

    public AppUser processOAuthPostLogin(String username, String email, String tenantId) {
        Optional<AppUser> optional = userRepository.findByUsername(username);
        AppUser user;

        // Usuario nuevo → lo marcamos como NO aprobado hasta que admin lo apruebe
        user = optional.orElseGet(() -> AppUser.builder()
                .username(username)
                .email(email)
                .tenantId(tenantId)
                .enabled(false)
                .build());

        // Verificamos si el usuario fue aprobado por el admin en Keycloak
        boolean isVerified = keycloakAdminService.isUserVerified(tenantId, username);
        user.setEnabled(isVerified);
        return userRepository.save(user);
    }
}
