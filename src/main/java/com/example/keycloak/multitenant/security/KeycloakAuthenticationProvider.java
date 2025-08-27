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
 * Custom {@link AuthenticationProvider} para integrar la autenticacion post-Keycloak
 * con Spring Security.
 * <p>
 * Este proveedor asume que la autenticacion de la contraseña ya fue realizada
 * por Keycloak a traves de un servicio de autenticacion externo. Su proposito
 * principal es:
 * <ul>
 * <li>Cargar los detalles del usuario (un {@link UserDetails} dummy) desde
 * un servicio para que el {@link SecurityContextHolder} de Spring Security
 * no contenga un usuario nulo.</li>
 * <li>Construir el token final de autenticacion con las autoridades correctas
 * extraidas de la autenticacion inicial, permitiendo la autorizacion basada en roles.</li>
 * </ul>
 *
 * @author Angel Fm
 * @version 1.0
 */
@Component
public class KeycloakAuthenticationProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(KeycloakAuthenticationProvider.class);

    private final UserDetailsService userDetailsService;

    /**
     * Constructor para la inyeccion de dependencias.
     * <p>
     *
     * @param userDetailsService El servicio para cargar los detalles del usuario.
     */
    public KeycloakAuthenticationProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * Procesa una solicitud de autenticacion.
     * <p>
     * Este metodo es llamado por Spring Security para autenticar a un usuario.
     * En este caso, valida la autenticacion pre-existente y la completa
     * con los detalles de usuario y roles.
     *
     * @param authentication El token de autenticacion de entrada, que ya contiene
     *                       el nombre de usuario y las autoridades extraidas.
     * @return Un token de autenticacion completamente poblado y autenticado.
     * @throws AuthenticationException Si la autenticacion no es valida.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();

        log.debug("KeycloakAuthenticationProvider: Procesando autenticacion para el usuario '{}'.", username);

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
     * <p>
     * Este proveedor solo soporta tokens de tipo {@link UsernamePasswordAuthenticationToken}.
     *
     * @param authentication La clase de token de autenticacion a verificar.
     * @return {@code true} si soporta el token, de lo contrario {@code false}.
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}