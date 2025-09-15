package com.example.keycloak.multitenant.service;

import com.example.keycloak.multitenant.security.PasswordTokenProvider;
import org.springframework.stereotype.Service;

/**
 * Servicio que orquesta el flujo de establecimiento de contraseñas.
 * <p>
 * Gestiona las operaciones de verificación de correo electrónico y
 * el reseteo de contraseñas, utilizando {@link PasswordTokenProvider}
 * para la validación de tokens y {@link UserService} para interactuar
 * con los datos de usuario.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class PasswordFlowService {

    private final PasswordTokenProvider tokenProvider;
    private final UserService userService;

    /**
     * Constructor para inyección de dependencias.
     *
     * @param tokenProvider El proveedor de tokens de contraseña.
     * @param userService   El servicio para la gestión de usuarios.
     */
    public PasswordFlowService(PasswordTokenProvider tokenProvider, UserService userService) {
        this.tokenProvider = tokenProvider;
        this.userService = userService;
    }

    /**
     * Valida el token enviado por correo electrónico y habilita/verifica el correo del usuario.
     * <p>
     * Este método se utiliza en el flujo de registro. Valida el token recibido por correo,
     * extrae el ID de usuario y luego habilita la cuenta del usuario y marca su correo como verificado.
     *
     * @param realm El nombre del realm de Keycloak.
     * @param token El token JWT recibido en el enlace de verificación.
     * @throws io.jsonwebtoken.JwtException si el token no es válido o ha expirado.
     */
    public void verifyEmail(String realm, String token) {
        String userId = tokenProvider.validateAndGetUserId(token);
        userService.enableAndVerifyEmail(realm, userId);
    }

    /**
     * Valida el token y establece la nueva contraseña del usuario.
     * <p>
     * Este método se utiliza para permitir que un usuario establezca su contraseña
     * por primera vez después de la verificación.
     *
     * @param realm    El nombre del realm de Keycloak.
     * @param token    El token JWT de validación.
     * @param password La nueva contraseña a establecer para el usuario.
     * @throws io.jsonwebtoken.JwtException si el token no es válido o ha expirado.
     */
    public void setPassword(String realm, String token, String password) {
        String userId = tokenProvider.validateAndGetUserId(token);
        userService.resetUserPassword(realm, userId, password);
    }
}
