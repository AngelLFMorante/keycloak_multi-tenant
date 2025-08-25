package com.example.keycloak.multitenant.security;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

/**
 * Custom AuthenticationProvider para integrar la autenticación post-Keycloak con Spring Security.
 * Este proveedor asume que la autenticación de la contraseña ya fue realizada por Keycloak.
 * Su propósito es solo cargar los UserDetails (dummy) y construir el token final de autenticación
 * con las autoridades correctas extraídas de Keycloak.
 */
@Component
public class KeycloakAuthenticationProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(KeycloakAuthenticationProvider.class);

    private final UserDetailsService userDetailsService;

    /**
     * Constructor para la inyeccion de dependencias.
     *
     * @param userDetailsService El servicio para cargar los detalles del usuario.
     */
    public KeycloakAuthenticationProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * Procesa una solicitud de autenticacion.
     * Este metodo es llamado por Spring Security para autenticar a un usuario.
     *
     * @param authentication El token de autenticacion de entrada.
     * @return Un token de autenticacion completamente poblado y autenticado.
     * @throws AuthenticationException Si la autenticacion falla.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();

        log.debug("KeycloakAuthenticationProvider: Procesando autenticación para el usuario '{}'.", username);

        // Cargar el UserDetails dummy. Esto es necesario para que Spring Security
        // tenga un UserDetails asociado al SecurityContext.
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // Devolvemos un UsernamePasswordAuthenticationToken *autenticado* con el UserDetails
        // y las autoridades que KeycloakController ya extrajo.
        @SuppressWarnings("unchecked")
        List<GrantedAuthority> authorities = (List<GrantedAuthority>) authentication.getAuthorities();

        Authentication finalAuth = new UsernamePasswordAuthenticationToken(
                userDetails,
                authentication.getCredentials(),
                authorities
        );
        log.debug("KeycloakAuthenticationProvider: Usuario '{}' autenticado y autoridades establecidas.", username);
        return finalAuth;
    }

    /**
     * Indica si este proveedor de autenticacion soporta el tipo de token de autenticacion dado.
     *
     * @param authentication La clase de token de autenticacion a verificar.
     * @return {@code true} si soporta el token, de lo contrario {@code false}.
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
