package com.example.keycloakdemo.config;

import com.example.keycloakdemo.repository.DynamicClientRegistrationRepository;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Configuración principal de seguridad para una aplicación multi-tenant con Keycloak.
 * Utiliza Spring Security para gestionar la autenticación y autorización,
 * soportando tanto un flujo de login manual (Password Grant Type) como la preparación
 * para un posible flujo OIDC (Authorization Code Flow).
 */
@Configuration
@EnableWebSecurity // Habilita la configuración de seguridad web de Spring.
public class SecurityConfig {

    /**
     * URL base del servidor de autenticación de Keycloak, inyectada desde las propiedades.
     */
    @Value("${keycloak.auth-server-url}")
    private String keycloakAuthServerUrl;

    /**
     * ID base del cliente de Keycloak, inyectado desde las propiedades.
     * Utilizado para configuraciones de cliente genéricas.
     */
    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String baseClientId;

    /**
     * Secreto base del cliente de Keycloak, inyectado desde las propiedades.
     * Utilizado para configuraciones de cliente genéricas y autenticación de cliente.
     */
    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String baseClientSecret;

    /**
     * Scopes base de OAuth2/OIDC solicitados, inyectados desde las propiedades.
     * Determinan qué información del usuario se solicitará a Keycloak.
     */
    @Value("${spring.security.oauth2.client.registration.keycloak.scope}")
    private String[] baseScopes;

    /**
     * Prefijo para los roles de Spring Security.
     * Los roles obtenidos de Keycloak se convertirán a este formato (ej. "ROLE_USER").
     */
    private final String KEYCLOAK_AUTHORITY_PREFIX = "ROLE_";

    /**
     * Contraseña dummy utilizada para el {@link UserDetailsService} y el {@link PasswordEncoder}
     * en el flujo de login manual.
     * Importante: NO USAR EN PRODUCCIÓN PARA CONTRSEÑAS REALES. Es solo para facilitar la integración
     * con el {@link DaoAuthenticationProvider} cuando Keycloak ya verificó la contraseña.
     */
    public static final String DUMMY_PASSWORD = "dummy_password";

    /**
     * Configura un repositorio dinámico de clientes OAuth2.
     * Esto es útil en un entorno multi-tenant donde los detalles del cliente
     * (como el realm) pueden variar.
     * @return Una instancia de {@link DynamicClientRegistrationRepository} que gestiona clientes de Keycloak.
     */
    @Bean
    public DynamicClientRegistrationRepository clientRegistrationRepository() {
        // Define un registro de cliente base para Keycloak con el flujo Authorization Code.
        ClientRegistration base = ClientRegistration.withRegistrationId("keycloak")
                .clientId(baseClientId) // ID del cliente base
                .clientSecret(baseClientSecret) // Secreto del cliente base
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Método de autenticación del cliente
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // Tipo de concesión de autorización
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}") // URI de redirección después de la autorización
                .scope(baseScopes) // Scopes OpenID Connect solicitados
                // URIs de Keycloak para los diferentes endpoints OIDC, dinámicos por realm
                .authorizationUri(keycloakAuthServerUrl + "/realms/{realmName}/protocol/openid-connect/auth")
                .tokenUri(keycloakAuthServerUrl + "/realms/{realmName}/protocol/openid-connect/token")
                .userInfoUri(keycloakAuthServerUrl + "/realms/{realmName}/protocol/openid-connect/userinfo")
                .jwkSetUri(keycloakAuthServerUrl + "/realms/{realmName}/protocol/openid-connect/certs")
                .issuerUri(keycloakAuthServerUrl + "/realms/{realmName}")
                .userNameAttributeName("preferred_username") // Atributo para el nombre de usuario
                .build();

        // Retorna un repositorio que puede crear registros de cliente dinámicamente.
        return new DynamicClientRegistrationRepository(keycloakAuthServerUrl, base);
    }

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
        http
                // Deshabilita la protección CSRF.
                // Esto es común para APIs REST o cuando la protección CSRF se maneja de forma diferente.
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        // Permite el acceso a recursos públicos sin autenticación.
                        .requestMatchers("/", "/public/**", "/error").permitAll()
                        // Permite el acceso a las páginas de login y registro por GET para cualquier realm.
                        .requestMatchers(HttpMethod.GET, "/{realm}/login", "/{realm}/register").permitAll()
                        // Permite el acceso a los endpoints de registro y login manual por POST para cualquier realm.
                        .requestMatchers(HttpMethod.POST, "/{realm}/register", "/{realm}/do_login").permitAll()

                        // Reglas de autorización específicas para rutas que requieren roles.
                        // Ejemplo: Solo usuarios con el rol 'USER_APP' pueden acceder a /plexus/home.
                        // Asegúrate de que 'USER_APP' es el nombre exacto del rol en Keycloak.
                        .requestMatchers("/{realm}/home").hasRole("USER_APP")
                        // .requestMatchers("/plexus/admin/**").hasRole("ADMIN_APP") // Ejemplo para rutas de administración

                        // Reglas de autorización generales:
                        // Todas las URLs bajo cualquier '{realm}' requieren autenticación.
                        .requestMatchers("/{realm}/**").authenticated()
                        // Cualquier otra solicitud (que no haya sido permitida o protegida antes)
                        // también requiere autenticación.
                        .anyRequest().authenticated()
                )
                // Configuración de logout.
                .logout(logout -> logout
                        .logoutUrl("/logout") // URL para iniciar el proceso de logout.
                        .logoutSuccessHandler(oidcLogoutSuccessHandler()) // Manejador post-logout.
                        .permitAll() // Permite que cualquier usuario acceda a la URL de logout.
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

        /*
         * NOTA: La siguiente sección está comentada pero muestra cómo se habilitaría
         * el flujo OAuth2 Login (Authorization Code Flow) si se quisiera usar
         * en conjunto o en lugar del Password Grant Type manual.
         * En este caso, el CustomAuthenticationSuccessHandler o un handler similar
         * se usaría aquí.
         */
        // .oauth2Login(oauth2 -> oauth2
        //     .clientRegistrationRepository(clientRegistrationRepository())
        //     .userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService()))
        //     .successHandler(authenticationSuccessHandler()) // Usar el handler que definimos abajo
        //     .defaultSuccessUrl("/home", true) // URL por defecto después del login de OAuth2
        // );

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
     * Un {@link PasswordEncoder} dummy.
     * No se usa para cifrar o verificar contraseñas de forma segura,
     * solo para satisfacer los requisitos del {@link DaoAuthenticationProvider}.
     * ¡No usar en producción para contraseñas locales o sensibles!
     * @return Una instancia de {@link NoOpPasswordEncoder} que no opera sobre las contraseñas.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance(); // No opera, solo devuelve la contraseña tal cual.
    }

    /**
     * Handler de éxito de autenticación para el flujo de login manual.
     * Se usa para persistir el objeto {@link Authentication} en la sesión HTTP
     * y redirigir al usuario después de un login exitoso.
     * Este bean ahora inyecta y utiliza el {@link CustomAuthenticationSuccessHandler}
     * para manejar la redirección dinámica basada en el tenant.
     * @param customAuthenticationSuccessHandler El manejador personalizado para redirecciones dinámicas.
     * @return Una instancia de {@link AuthenticationSuccessHandler}.
     */
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler(CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler) {
        // Inyectamos y usamos el CustomAuthenticationSuccessHandler
        // Este handler es el que tiene la lógica para redirigir a /{tenant}/home.
        return customAuthenticationSuccessHandler;
    }

    /**
     * Define un {@link SecurityContextRepository} para gestionar cómo se guarda
     * y recupera el {@link SecurityContext} en la {@link jakarta.servlet.http.HttpSession}.
     * Esto es crucial para la persistencia de la autenticación entre peticiones.
     * @return Una instancia de {@link HttpSessionSecurityContextRepository}.
     */
    @Bean
    public SecurityContextRepository securityContextRepository() {
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
    public LogoutSuccessHandler oidcLogoutSuccessHandler() {
        return (request, response, authentication) -> {
            // Solo procesa si la autenticación es de tipo OIDC (si se usó el flujo OAuth2 Login).
            if (authentication != null && authentication.getPrincipal() instanceof OidcUser oidcUser) {
                String issuer = oidcUser.getIssuer().toString(); // URL del emisor de Keycloak.
                String idToken = oidcUser.getIdToken().getTokenValue(); // ID Token para el logout de sesión IdP.
                String logoutUrl = issuer + "/protocol/openid-connect/logout"; // Endpoint de logout de Keycloak.

                // Construye la URI de redirección post-logout de la aplicación.
                // Redirige a la raíz de la aplicación.
                String redirectUri = UriComponentsBuilder
                        .fromHttpUrl(request.getRequestURL().toString())
                        .replacePath("/")
                        .build()
                        .toUriString();

                String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

                // Construye la URL final de logout de Keycloak con parámetros.
                String finalLogoutUrl = UriComponentsBuilder.fromHttpUrl(logoutUrl)
                        .queryParam("id_token_hint", idToken) // Pista del ID Token para Keycloak.
                        .queryParam("post_logout_redirect_uri", encodedRedirectUri) // URI de redirección de vuelta a la app.
                        .build()
                        .toUriString();

                System.out.println("===> Logout desde LogoutSuccessHandler OIDC: Redirigiendo a Keycloak.");
                response.sendRedirect(finalLogoutUrl); // Redirige al navegador al endpoint de logout de Keycloak.
            } else {
                // Si el usuario no fue autenticado vía OIDC (ej. por tu flujo manual),
                // simplemente invalida la sesión local y redirige a la página de login general.
                if (request.getSession(false) != null) {
                    request.getSession(false).invalidate(); // Invalida la sesión HTTP local.
                }
                System.out.println("===> Logout sin usuario OIDC, invalidando sesión local y redirigiendo a /login.");
                response.sendRedirect("/login"); // Redirige a la página de login.
            }
        };
    }
}
