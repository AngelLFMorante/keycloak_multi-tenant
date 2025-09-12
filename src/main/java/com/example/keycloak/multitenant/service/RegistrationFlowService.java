package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.config.AppProperties;
import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.security.PasswordTokenProvider;
import com.example.keycloak.multitenant.service.mail.MailService;
import org.springframework.stereotype.Service;

@Service
public class RegistrationFlowService {

    private final PasswordTokenProvider tokenProvider;
    private final MailService mailService;
    private final AppProperties appProperties;

    public RegistrationFlowService(PasswordTokenProvider tokenProvider, MailService mailService, AppProperties appProperties) {
        this.tokenProvider = tokenProvider;
        this.mailService = mailService;
        this.appProperties = appProperties;
    }

    /**
     * Inicia el flujo de establecimiento de contraseña para un usuario recién creado.
     *
     * @param realmPath Realm / tenant del usuario
     * @param userId    ID del usuario en Keycloak
     * @param request   Datos del usuario
     */
    public void startSetPasswordFlow(String realmPath, String userId, UserRequest request) {
        // Genera token seguro para que el usuario establezca su contraseña
        String token = tokenProvider.generateToken(userId);

        // Construye el link que se enviará por email
        String link = String.format("%s/%s/password/set?token=%s", appProperties.getBaseUrl(), realmPath, token);

        // Envía el email
        mailService.sendSetPasswordEmail(request.email(), request.username(), link);
    }
}
