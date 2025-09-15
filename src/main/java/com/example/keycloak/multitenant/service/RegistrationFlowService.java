package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.config.AppProperties;
import com.example.keycloak.multitenant.model.user.UserRequest;
import com.example.keycloak.multitenant.security.PasswordTokenProvider;
import com.example.keycloak.multitenant.service.mail.MailService;
import org.springframework.stereotype.Service;

/**
 * Servicio que orquesta el flujo de registro de usuarios.
 * <p>
 * Se encarga de la lógica para iniciar el proceso de verificación de correo
 * electrónico y el establecimiento de contraseña, utilizando un token seguro
 * y el servicio de correo para notificar al usuario.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class RegistrationFlowService {

    private final PasswordTokenProvider tokenProvider;
    private final MailService mailService;
    private final AppProperties appProperties;

    /**
     * Constructor para inyección de dependencias.
     *
     * @param tokenProvider El proveedor de tokens de contraseña.
     * @param mailService   El servicio para el envío de correos electrónicos.
     * @param appProperties Las propiedades de la aplicación.
     */
    public RegistrationFlowService(PasswordTokenProvider tokenProvider, MailService mailService, AppProperties appProperties) {
        this.tokenProvider = tokenProvider;
        this.mailService = mailService;
        this.appProperties = appProperties;
    }

    /**
     * Inicia el flujo de establecimiento de contraseña para un usuario recién creado.
     * <p>
     * Este método genera un token de un solo uso para el usuario, construye el
     * enlace de activación y envía un correo electrónico al usuario para que
     * pueda verificar su cuenta y establecer su contraseña.
     *
     * @param realmPath El nombre del realm (tenant).
     * @param userId    El ID del usuario en Keycloak.
     * @param request   Los datos del usuario, incluyendo el email.
     */
    public void startSetPasswordFlow(String realmPath, String userId, UserRequest request) {
        // Genera token seguro para que el usuario establezca su contraseña
        String token = tokenProvider.generateToken(userId);

        // Construye el link que se enviará por email
        // El link debe coincidir con la ruta del controlador que maneja la solicitud GET,
        // que en este caso es /verify.
        String link = String.format("%s/%s/password/verify?token=%s", appProperties.getBaseUrl(), realmPath, token);

        // Envía el email
        mailService.sendSetPasswordEmail(request.email(), request.username(), link);
    }
}
