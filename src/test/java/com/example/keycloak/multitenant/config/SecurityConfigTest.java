package com.example.keycloak.multitenant.config;

import com.example.keycloak.multitenant.security.KeycloakAuthenticationProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.WebApplicationContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.logout;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext applicationContext;

    private SecurityConfig securityConfig;

    @Autowired(required = false)
    private ObjectMapper objectMapper;

    @Mock
    private KeycloakAuthenticationProvider mockKeycloakAuthenticationProvider;

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private HttpServletResponse mockResponse;

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private HttpSession mockSession;

    private KeycloakProperties keycloakProperties;


    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(applicationContext)
                .apply(springSecurity())
                .build();

        keycloakProperties = new KeycloakProperties();
        Map<String, String> realmMapping = new HashMap<>();
        realmMapping.put("test-realm", "realm-test-id");

        Map<String, String> clientSecrets = new HashMap<>();
        clientSecrets.put("test-client", "secret123");

        keycloakProperties.setRealmMapping(realmMapping);
        keycloakProperties.setClientSecrets(clientSecrets);

        securityConfig = new SecurityConfig(keycloakProperties);
    }

    @Test
    @DisplayName("Debería permitir acceso POST a /realm/register sin autenticación")
    void securityFilterChain_shouldPermitPostRegister() throws Exception {
        String jsonBody = "{\"username\":\"test\",\"email\":\"test@example.com\",\"password\":\"password\",\"confirmPassword\":\"password\"}";
        mockMvc.perform(post("/any-realm/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonBody))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("CSRF debería estar deshabilitado")
    void securityFilterChain_csrfShouldBeDisabled() throws Exception {
        String jsonBody = "{\"username\":\"test\",\"email\":\"test@example.com\",\"password\":\"password\",\"confirmPassword\":\"password\"}";
        mockMvc.perform(post("/any-realm/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonBody))
                .andExpect(status().isBadRequest()); // Sigue siendo 400 del controlador, no 403 CSRF.
    }

    @Test
    @DisplayName("El endpoint de logout debería funcionar y limpiar la autenticación")
    @WithMockUser("testuser")
    void securityFilterChain_logoutShouldWork() throws Exception {
        mockMvc.perform(logout("/logout"))
                .andExpect(status().isOk())
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("authenticationManager debería ser un ProviderManager y contener KeycloakAuthenticationProvider")
    void authenticationManager_shouldBeProviderManagerWithKeycloakProvider() {
        AuthenticationManager manager = securityConfig.authenticationManager(mockKeycloakAuthenticationProvider);

        assertNotNull(manager);
        assertTrue(manager instanceof ProviderManager);
        ProviderManager providerManager = (ProviderManager) manager;
        assertTrue(providerManager.getProviders().contains(mockKeycloakAuthenticationProvider));
        assertEquals(1, providerManager.getProviders().size());
    }

    @Test
    @DisplayName("userDetailsService debería devolver un UserDetails con la contraseña dummy")
    void userDetailsService_shouldReturnUserDetailsWithDummyPassword() {
        UserDetailsService service = securityConfig.userDetailsService();
        assertNotNull(service);

        String username = "testuser";
        UserDetails userDetails = service.loadUserByUsername(username);

        assertNotNull(userDetails);
        assertEquals(username, userDetails.getUsername());
        assertEquals(SecurityConfig.DUMMY_PASSWORD, userDetails.getPassword());
        assertTrue(userDetails.getAuthorities().isEmpty());
        assertTrue(userDetails.isEnabled());
        assertTrue(userDetails.isAccountNonExpired());
        assertTrue(userDetails.isAccountNonLocked());
        assertTrue(userDetails.isCredentialsNonExpired());
    }

    @Test
    @DisplayName("securityContextRepository debería ser HttpSessionSecurityContextRepository")
    void securityContextRepository_shouldBeHttpSessionSecurityContextRepository() {
        SecurityContextRepository repository = securityConfig.securityContextRepository();
        assertNotNull(repository);
        assertTrue(repository instanceof HttpSessionSecurityContextRepository);
    }

    @Test
    @DisplayName("restTemplate debería devolver una instancia de RestTemplate")
    void restTemplate_shouldReturnRestTemplateInstance() {
        RestTemplate restTemplate = securityConfig.restTemplate();
        assertNotNull(restTemplate);
        assertTrue(restTemplate instanceof RestTemplate);
    }

    @Test
    @DisplayName("customLogoutSuccessHandler debería ser un LogoutSuccessHandler y establecer el estado OK")
    void customLogoutSuccessHandler_shouldSetStatusOk() throws Exception {
        LogoutSuccessHandler handler = securityConfig.customLogoutSuccessHandler(new RestTemplate());
        assertNotNull(handler);

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        Authentication mockAuthentication = mock(Authentication.class);

        when(mockAuthentication.getName()).thenReturn("testUser");

        handler.onLogoutSuccess(mockRequest, mockResponse, mockAuthentication);

        verify(mockResponse, times(1)).setStatus(HttpStatus.OK.value());
        verify(mockAuthentication, times(1)).getName();
    }

    @Test
    @DisplayName("Debería revocar el refresh token cuando la sesión contiene refreshToken, realm y clientUsed")
    @WithMockUser("testuser")
    void shouldRevokeRefreshTokenOnLogout() throws Exception {
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("refreshToken")).thenReturn("dummy-refresh-token");
        when(mockSession.getAttribute("realm")).thenReturn("test-realm");
        when(mockSession.getAttribute("clientUsed")).thenReturn("test-client");

        ResponseEntity<String> mockResponseEntity = ResponseEntity.ok("Success");

        when(restTemplate.postForEntity(anyString(), any(), eq(String.class)))
                .thenReturn(mockResponseEntity);

        LogoutSuccessHandler handler = securityConfig.customLogoutSuccessHandler(restTemplate);
        handler.onLogoutSuccess(mockRequest, mockResponse, mock(Authentication.class));

        verify(restTemplate, times(1)).postForEntity(anyString(), any(), eq(String.class));
        verify(mockResponse, times(1)).setStatus(HttpStatus.OK.value());
    }


    @Test
    @DisplayName("Debería manejar excepción al intentar revocar el refresh token")
    @WithMockUser("testuser")
    void shouldHandleExceptionWhenRevokingRefreshToken() throws Exception {
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("refreshToken")).thenReturn("dummy-refresh-token");
        when(mockSession.getAttribute("realm")).thenReturn("test-realm");
        when(mockSession.getAttribute("clientUsed")).thenReturn("test-client");

        doThrow(new RuntimeException("Error al intentar revocar el token")).when(restTemplate)
                .postForEntity(anyString(), any(), eq(String.class));

        LogoutSuccessHandler handler = securityConfig.customLogoutSuccessHandler(restTemplate);
        handler.onLogoutSuccess(mockRequest, mockResponse, mock(Authentication.class));

        verify(restTemplate, times(1)).postForEntity(anyString(), any(), eq(String.class));
        verify(mockResponse, times(1)).setStatus(HttpStatus.OK.value());
    }


    @Test
    @DisplayName("No debería revocar el refresh token si faltan refreshToken, realm o clientUsed en la sesión")
    @WithMockUser("testuser")
    void shouldNotRevokeRefreshTokenIfMissingSessionAttributes() throws Exception {
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("refreshToken")).thenReturn(null);
        when(mockSession.getAttribute("realm")).thenReturn("test-realm");
        when(mockSession.getAttribute("clientUsed")).thenReturn("test-client");

        LogoutSuccessHandler handler = securityConfig.customLogoutSuccessHandler(restTemplate);
        handler.onLogoutSuccess(mockRequest, mockResponse, mock(Authentication.class));

        verify(restTemplate, times(0)).postForEntity(anyString(), any(), eq(String.class));
        verify(mockResponse, times(1)).setStatus(HttpStatus.OK.value());
    }

    @Test
    @DisplayName("Debería no revocar el token si keycloakRealm o clientSecret son null")
    void shouldNotRevokeIfKeycloakRealmOrClientSecretAreNull() throws Exception {
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("refreshToken")).thenReturn("dummy-refresh-token");
        when(mockSession.getAttribute("realm")).thenReturn("realm-sin-mapeo");
        when(mockSession.getAttribute("clientUsed")).thenReturn("client-sin-secreto");

        KeycloakProperties keycloakProperties = new KeycloakProperties();
        keycloakProperties.setAuthServerUrl("http://localhost:8080");
        keycloakProperties.setRealmMapping(new HashMap<>());
        keycloakProperties.setClientSecrets(new HashMap<>());

        SecurityConfig config = new SecurityConfig(keycloakProperties);
        LogoutSuccessHandler handler = config.customLogoutSuccessHandler(restTemplate);

        handler.onLogoutSuccess(mockRequest, mockResponse, mock(Authentication.class));

        verify(mockResponse, times(1)).setStatus(HttpStatus.OK.value());
        verify(restTemplate, times(0)).postForEntity(anyString(), any(), eq(String.class));
    }

}