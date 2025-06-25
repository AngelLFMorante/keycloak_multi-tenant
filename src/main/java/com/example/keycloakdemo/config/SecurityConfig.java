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
import org.springframework.security.web.context.HttpSessionSecurityContextRepository; // Importar
import org.springframework.security.web.context.SecurityContextRepository; // Importar
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Configuración principal de seguridad para multi-tenant con Keycloak.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${keycloak.auth-server-url}")
    private String keycloakAuthServerUrl;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String baseClientId;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String baseClientSecret;

    @Value("${spring.security.oauth2.client.registration.keycloak.scope}")
    private String[] baseScopes;

    private final String KEYCLOAK_AUTHORITY_PREFIX = "ROLE_";
    public static final String DUMMY_PASSWORD = "dummy_password"; // ¡Importante!

    /**
     * Repositorio dinámico de clientes OAuth2 para multi-tenant.
     * (Mantener si planeas usar también el Authorization Code Flow en algún momento)
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration base = ClientRegistration.withRegistrationId("keycloak")
                .clientId(baseClientId)
                .clientSecret(baseClientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(baseScopes)
                .authorizationUri(keycloakAuthServerUrl + "/realms/{realmName}/protocol/openid-connect/auth")
                .tokenUri(keycloakAuthServerUrl + "/realms/{realmName}/protocol/openid-connect/token")
                .userInfoUri(keycloakAuthServerUrl + "/realms/{realmName}/protocol/openid-connect/userinfo")
                .jwkSetUri(keycloakAuthServerUrl + "/realms/{realmName}/protocol/openid-connect/certs")
                .issuerUri(keycloakAuthServerUrl + "/realms/{realmName}")
                .userNameAttributeName("preferred_username")
                .build();

        return new DynamicClientRegistrationRepository(keycloakAuthServerUrl, base);
    }

    /**
     * Configuración de seguridad HTTP con formLogin clásico y URLs explícitas para cada tenant.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        // Recursos públicos (CSS, JS, etc.)
                        .requestMatchers("/", "/public/**", "/error").permitAll()
                        // Rutas de login y registro por realm
                        .requestMatchers(HttpMethod.GET, "/{realm}/login", "/{realm}/register").permitAll()
                        .requestMatchers(HttpMethod.POST, "/{realm}/register", "/{realm}/do_login").permitAll()
                        // Rutas específicas que requieren roles
                        .requestMatchers("/plexus/home").hasRole("USER_APP") // Asume que 'USER_APP' es un rol en Keycloak
                        // .requestMatchers("/plexus/admin/**").hasRole("ADMIN_APP") // Ejemplo de ruta de admin
                        // Rutas generales que solo requieren autenticación
                        .requestMatchers("/{realm}/**").authenticated() // Asegúrate de que todas las URLs bajo un realm están protegidas
                        .anyRequest().authenticated() // Cualquier otra ruta, si la hay, también autenticada
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(oidcLogoutSuccessHandler()) // Se encargará de redirigir después del logout
                        .permitAll() // Permite a todos acceder al logout
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                         // Protege contra ataques de fijación de sesión
                );

        return http.build();
    }

    // --- BEANS NECESARIOS PARA EL LOGIN MANUAL EN LoginController ---

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(authProvider);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            return User.withUsername(username)
                    .password(DUMMY_PASSWORD) // Debe coincidir con la de LoginController
                    .authorities(Collections.emptyList())
                    .build();
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        // Redirige siempre a la URL por defecto después de un login exitoso
        SimpleUrlAuthenticationSuccessHandler handler = new SimpleUrlAuthenticationSuccessHandler("/plexus/home");
        handler.setAlwaysUseDefaultTargetUrl(true); // Siempre redirigir a /plexus/home si no hay targetUrl guardada
        return handler;
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    // --- FIN DE BEANS NECESARIOS PARA EL LOGIN MANUAL ---


    /**
     * Servicio para extraer roles del token OIDC.
     * (Esto es para el flujo OAuth2 Login, no para tu Password Grant Type manual).
     */
    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            OidcUser oidcUser = delegate.loadUser(userRequest);
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            Map<String, Object> realmAccess = oidcUser.getClaimAsMap("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                Collection<String> realmRoles = (Collection<String>) realmAccess.get("roles");
                realmRoles.forEach(role -> mappedAuthorities.add(new SimpleGrantedAuthority(KEYCLOAK_AUTHORITY_PREFIX + role.toUpperCase())));
            }

            Map<String, Object> resourceAccess = oidcUser.getClaimAsMap("resource_access");
            if (resourceAccess != null) {
                String currentClientId = userRequest.getClientRegistration().getClientId();
                Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(currentClientId);
                if (clientAccess != null && clientAccess.containsKey("roles")) {
                    Collection<String> clientRoles = (Collection<String>) clientAccess.get("roles");
                    clientRoles.forEach(role -> mappedAuthorities.add(new SimpleGrantedAuthority(KEYCLOAK_AUTHORITY_PREFIX + role.toUpperCase())));
                }
            }

            mappedAuthorities.addAll(oidcUser.getAuthorities());

            return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
        };
    }

    /**
     * Logout personalizado para Keycloak.
     */
    @Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler() {
        return (request, response, authentication) -> {
            if (authentication != null && authentication.getPrincipal() instanceof OidcUser oidcUser) {
                String issuer = oidcUser.getIssuer().toString();
                String idToken = oidcUser.getIdToken().getTokenValue();
                String logoutUrl = issuer + "/protocol/openid-connect/logout";

                String redirectUri = UriComponentsBuilder
                        .fromHttpUrl(request.getRequestURL().toString())
                        .replacePath("/")
                        .build()
                        .toUriString();

                String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

                String finalLogoutUrl = UriComponentsBuilder.fromHttpUrl(logoutUrl)
                        .queryParam("id_token_hint", idToken)
                        .queryParam("post_logout_redirect_uri", encodedRedirectUri)
                        .build()
                        .toUriString();

                System.out.println("===> Logout desde LogoutSuccessHandler OIDC");
                response.sendRedirect(finalLogoutUrl);
            } else {
                System.out.println("===> Logout sin usuario OIDC, redirigiendo a /login");
                // Si el usuario no fue autenticado vía OIDC (ej. por tu flujo manual),
                // simplemente redirige a la página de login general.
                response.sendRedirect("/login");
            }
        };
    }
}