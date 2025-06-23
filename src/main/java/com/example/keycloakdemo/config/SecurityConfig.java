package com.example.keycloakdemo.config;

import com.example.keycloakdemo.repository.DynamicClientRegistrationRepository;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Configuración principal de seguridad para OAuth2 multi-tenant con Keycloak.
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

    private final CustomAuthenticationSuccessHandler successHandler;

    public SecurityConfig(CustomAuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
    }

    /**
     * Configura el repositorio de clientes OAuth2 usando un registro dinámico por tenant.
     *
     * @return Repositorio dinámico de registros de cliente.
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
     * Configura la cadena de filtros de seguridad HTTP para manejar las rutas protegidas y públicas.
     *
     * @param http Configuración del objeto HttpSecurity.
     * @return Cadena de filtros configurada.
     * @throws Exception Si ocurre un error en la configuración.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/public/**", "/error").permitAll()
                        .requestMatchers("/plexus/login", "/inditex/login").permitAll()
                        .requestMatchers(HttpMethod.GET, "/plexus/register").permitAll()
                        .requestMatchers(HttpMethod.POST, "/plexus/register").permitAll()
                        .requestMatchers("/plexus/**", "/inditex/**").authenticated()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2Login -> oauth2Login
                        .userInfoEndpoint(userInfo -> userInfo
                                .oidcUserService(this.oidcUserService())
                        )
                        .successHandler(successHandler)
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(oidcLogoutSuccessHandler())
                );
        return http.build();
    }

    /**
     * Servicio personalizado para extraer roles desde el ID Token de Keycloak.
     *
     * @return Servicio OIDC de usuario extendido.
     */
    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            OidcUser oidcUser = delegate.loadUser(userRequest);
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            // Extrae roles de realm_access.roles
            Map<String, Object> realmAccess = oidcUser.getClaimAsMap("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                Collection<String> realmRoles = (Collection<String>) realmAccess.get("roles");
                realmRoles.forEach(role -> mappedAuthorities.add(new SimpleGrantedAuthority(KEYCLOAK_AUTHORITY_PREFIX + role.toUpperCase())));
            }

            // Extrae roles de resource_access.<client-id>.roles
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
     * Manejador personalizado para logout que redirige a la raíz de la aplicación.
     *
     * @return Manejador de logout exitoso.
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

                System.out.println("===> Logout desde LogoutSuccessHandler");
                response.sendRedirect(finalLogoutUrl);
            } else {
                System.out.println("===> Logout sin usuario, redirigiendo a raíz");
                response.sendRedirect("/");
            }
        };
    }

}
