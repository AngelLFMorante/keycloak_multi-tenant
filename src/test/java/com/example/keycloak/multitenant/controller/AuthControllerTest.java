package com.example.keycloak.multitenant.controller;

import com.example.keycloak.multitenant.controller.api.AuthController;
import com.example.keycloak.multitenant.model.token.ClientCredentialsTokenResponse;
import com.example.keycloak.multitenant.model.token.RefreshTokenRequest;
import com.example.keycloak.multitenant.model.token.TokenValidationResponse;
import com.example.keycloak.multitenant.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    private MockMvc mockMvc;

    @Mock
    private AuthService authService;

    @InjectMocks
    private AuthController authController;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(authController).build();
    }

    @Test
    @DisplayName("Debería retornar 200 OK y una respuesta de validación activa para un token válido")
    void validateToken_shouldReturn200AndActiveResponse_whenTokenIsValid() throws Exception {
        String token = "valid_token";
        RefreshTokenRequest request = new RefreshTokenRequest(token);

        TokenValidationResponse validResponse = new TokenValidationResponse(
                true, // active
                "Bearer", // tokenType
                "scope-1", // scope
                "sub-123", // sub
                "session-state-1", // sessionState
                Collections.singletonList("test-client"), // aud
                "https://test.keycloak.com/realms/test-realm", // iss
                1730000000L, // exp
                "test-client", // azp
                null // error
        );

        when(authService.validateToken(any(RefreshTokenRequest.class), anyString(), anyString()))
                .thenReturn(validResponse);

        mockMvc.perform(post("/api/v1/{realm}/auth/{client}/validate", "test-realm", "test-client")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.sub").value("sub-123"));
    }

    @Test
    @DisplayName("Debería retornar 401 Unauthorized y una respuesta de validación inactiva para un token inválido")
    void validateToken_shouldReturn401AndInactiveResponse_whenTokenIsInvalid() throws Exception {
        String token = "invalid_token";
        RefreshTokenRequest request = new RefreshTokenRequest(token);

        TokenValidationResponse invalidResponse = new TokenValidationResponse(
                false, // active
                null, // tokenType
                null, // scope
                null, // sub
                null, // sessionState
                null, // aud
                null, // iss
                0L, // exp
                null, // azp
                "Token invalido" // error
        );

        when(authService.validateToken(any(RefreshTokenRequest.class), anyString(), anyString()))
                .thenReturn(invalidResponse);

        mockMvc.perform(post("/api/v1/{realm}/auth/{client}/validate", "test-realm", "test-client")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.active").value(false));
    }

    @Test
    @DisplayName("Debería retornar 200 OK y un token para Client Credentials")
    void getClientCredentialsToken_shouldReturn200AndTokenResponse() throws Exception {
        ClientCredentialsTokenResponse mockTokenResponse = new ClientCredentialsTokenResponse(
                "access_token_abc", 3600, 0, "test-scope", "scope-1"
        );

        when(authService.getClientCredentialsToken(anyString(), anyString()))
                .thenReturn(mockTokenResponse);

        mockMvc.perform(post("/api/v1/{realm}/auth/{client}/token", "test-realm", "test-client")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("access_token_abc"))
                .andExpect(jsonPath("$.expires_in").value(3600))
                .andExpect(jsonPath("$.token_type").value("test-scope"));
    }
}
