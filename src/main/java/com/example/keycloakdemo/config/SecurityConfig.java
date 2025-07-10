package com.example.keycloakdemo.config;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Configuración principal de seguridad para una aplicación multi-tenant con Keycloak.
 * Adaptada para funcionar como un microservicio REST, centrado en el flujo
 * de login manual (Password Grant Type) y unico realm de Keycloak con multiples clientes.
 */
@Configuration
@EnableWebSecurity // Habilita la configuración de seguridad web de Spring.
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    /**
     * URL base del servidor de autenticación de Keycloak, inyectada desde las propiedades.
     */
    @Value("${keycloak.auth-server-url}")
    private String keycloakAuthServerUrl;

    /**
     * Prefijo para los roles de Spring Security.
     * Los roles obtenidos de Keycloak se convertirán a este formato (ej. "ROLE_USER").
     */
    private final String KEYCLOAK_AUTHORITY_PREFIX = "ROLE_";

    /**
     * Contraseña dummy utilizada para el {@link UserDetailsService} y el {@link PasswordEncoder}
     * en el flujo de login manual.
     * Importante: NO USAR EN PRODUCCIÓN PARA CONTRASEÑAS REALES. Es solo para facilitar la integración
     * con el {@link DaoAuthenticationProvider} cuando Keycloak ya verificó la contraseña.
     */
    public static final String DUMMY_PASSWORD = "dummy_password";


    /**
     * Configura la cadena de filtros de seguridad HTTP.
     * Define las reglas de autorización para diferentes rutas y gestiona el logout y las sesiones.
     *
     * @param http El objeto {@link HttpSecurity} para configurar la seguridad web.
     * @return Un {@link SecurityFilterChain} configurado.
     * @throws Exception Si ocurre un error durante la configuración de seguridad.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("Configurando SecurityFilterChain para el microservicio REST.");

        http
                // Deshabilita la protección CSRF.
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        // Permite el acceso a recursos públicos sin autenticación.
                        .requestMatchers("/", "/public/**", "/error").permitAll()
                        // Permite el acceso a las páginas de login y registro por GET para cualquier realm.
                        .requestMatchers(HttpMethod.GET, "/{realm}/login", "/{realm}/register").permitAll()
                        // Permite el acceso a los endpoints de registro y login manual por POST para cualquier realm.
                        .requestMatchers(HttpMethod.POST, "/{realm}/register", "/{realm}/{client}/do_login").permitAll()
                        // Cualquier otra solicitud (que no haya sido permitida o protegida antes)
                        // también requiere autenticación.
                        .anyRequest().authenticated()
                )
                // Configuración de logout.
                .logout(logout -> logout
                        .logoutUrl("/logout") // URL para iniciar el proceso de logout.
                        .logoutSuccessHandler(customLogoutSuccessHandler()) // Manejador post-logout.
                        .permitAll() // Permite que cualquier usuario acceda a la URL de logout.
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                )
                // Configuración de gestión de sesiones.
                .sessionManagement(session -> session
                        // Protege contra ataques de fijación de sesión migrando la sesión existente.
                        .sessionFixation().migrateSession()
                        // IF_REQUIRED: Spring Security creará una sesión si es necesaria.
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        // Limita el número de sesiones concurrentes para un usuario.
                        .maximumSessions(1)
                        // Si un nuevo login excede el máximo, no previene el nuevo login,
                        // sino que invalida la sesión más antigua.
                        .maxSessionsPreventsLogin(false)
                );
        log.info("SecurityFilterChain configurado.");
        return http.build();
    }

    // --- BEANS NECESARIOS PARA EL LOGIN MANUAL EN LoginController ---
    // Estos beans son cruciales para integrar el flujo de autenticación manual
    // (Password Grant Type) con el sistema de seguridad de Spring.

    /**
     * Define un {@link AuthenticationManager} que permite a Spring Security
     * registrar la autenticación después de que Keycloak la haya verificado.
     * Utiliza un {@link DaoAuthenticationProvider} con componentes dummy.
     * @param userDetailsService El {@link UserDetailsService} dummy para la carga de usuarios.
     * @param passwordEncoder El {@link PasswordEncoder} dummy para la verificación de contraseñas.
     * @return Una instancia de {@link AuthenticationManager}.
     */
    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        log.debug("Configurando AuthenticationManager.");
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(authProvider);
    }

    /**
     * Un {@link UserDetailsService} dummy.
     * No se usa para verificar la contraseña (Keycloak ya lo hizo),
     * sino para que el {@link DaoAuthenticationProvider} tenga un componente
     * {@link UserDetailsService}. Los detalles del usuario (incluidos los roles
     * que serán añadidos al token final) ya provienen de Keycloak.
     * @return Una instancia de {@link UserDetailsService} que devuelve un usuario con una contraseña dummy.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        log.debug("Configurando UserDetailsService dummy.");
        return username -> {
            // Se asume que el usuario ya ha sido autenticado por Keycloak.
            // La contraseña debe coincidir con DUMMY_PASSWORD para que el DaoAuthenticationProvider no falle.
            return User.withUsername(username)
                    .password(DUMMY_PASSWORD) // Contraseña dummy, solo para satisfacer la verificación del provider.
                    .authorities(Collections.emptyList()) // Los roles reales se establecerán en el AuthenticationToken en LoginController.
                    .build();
        };
    }

    /**
     * Define un {@link PasswordEncoder} seguro para Spring Security.
     * Aunque la verificación real de la contraseña la hace Keycloak, este bean es necesario
     * para satisfacer los requisitos del {@link DaoAuthenticationProvider}.
     * @return Una instancia de {@link BCryptPasswordEncoder}.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        log.debug("Configurando PasswordEncoder con BCryptPasswordEncoder.");
        return new BCryptPasswordEncoder(); // No opera, solo devuelve la contraseña tal cual.
    }

    /**
     * Define un {@link SecurityContextRepository} para gestionar cómo se guarda
     * y recupera el SecurityContext en la {@link jakarta.servlet.http.HttpSession}.
     * Esto es crucial para la persistencia de la autenticación entre peticiones.
     * @return Una instancia de {@link HttpSessionSecurityContextRepository}.
     */
    @Bean
    public SecurityContextRepository securityContextRepository() {
        log.debug("Configurando SecurityContextRepository.");
        return new HttpSessionSecurityContextRepository();
    }

    // --- FIN DE BEANS NECESARIOS PARA EL LOGIN MANUAL ---


    /**
     * Servicio para extraer roles del token OIDC cuando se utiliza el flujo OAuth2 Login.
     * Este método mapea los roles de Keycloak (realm y cliente) a autoridades de Spring Security.
     * Es relevante si también se habilita el `.oauth2Login()` en el {@link SecurityFilterChain}.
     * @return Un {@link OAuth2UserService} que procesa la información del usuario OIDC.
     */
    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        log.debug("Configurando OidcUserService (manteniendo para posible uso futuro de OAuth2 Login).");
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            OidcUser oidcUser = delegate.loadUser(userRequest); // Carga el usuario OIDC estándar.
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            // Extrae roles de 'realm_access' del token de identidad.
            Map<String, Object> realmAccess = oidcUser.getClaimAsMap("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                Collection<String> realmRoles = (Collection<String>) realmAccess.get("roles");
                realmRoles.forEach(role -> mappedAuthorities.add(new SimpleGrantedAuthority(KEYCLOAK_AUTHORITY_PREFIX + role.toUpperCase())));
            }

            // Extrae roles de 'resource_access' (roles de cliente) del token de identidad.
            Map<String, Object> resourceAccess = oidcUser.getClaimAsMap("resource_access");
            if (resourceAccess != null) {
                // Obtiene el ID del cliente actual para buscar roles específicos de ese cliente.
                String currentClientId = userRequest.getClientRegistration().getClientId();
                Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(currentClientId);
                if (clientAccess != null && clientAccess.containsKey("roles")) {
                    Collection<String> clientRoles = (Collection<String>) clientAccess.get("roles");
                    clientRoles.forEach(role -> mappedAuthorities.add(new SimpleGrantedAuthority(KEYCLOAK_AUTHORITY_PREFIX + role.toUpperCase())));
                }
            }

            // Añade las autoridades originales (por ejemplo, 'SCOPE_openid') si existen.
            mappedAuthorities.addAll(oidcUser.getAuthorities());

            // Devuelve un nuevo OidcUser con las autoridades mapeadas.
            return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
        };
    }

    /**
     * Manejador de éxito de logout personalizado para Keycloak.
     * Redirige al usuario al endpoint de logout de Keycloak para finalizar la sesión en el IdP,
     * y luego a una URI de post-logout de la aplicación.
     * @return Un {@link LogoutSuccessHandler} configurado.
     */
    @Bean
    public LogoutSuccessHandler customLogoutSuccessHandler() {
        log.debug("Configurando CustomLogoutSuccessHandler para microservicio REST.");
        return (request, response, authentication) -> {
            // Invalida la sesión local de Spring Security.
            // La eliminación de cookies y la invalidación de sesion ya están configuradas
            // en el .logout() de la SecurityFilterChain.
            // simplemente aseguramos que la sesion local se limpie.
            log.info("Logout exitoso para el usuario '{}'. Sesión local invalidada.", authentication != null ? authentication.getName() : "desconocido");
            response.setStatus(HttpStatus.OK.value());
        };
    }
}
