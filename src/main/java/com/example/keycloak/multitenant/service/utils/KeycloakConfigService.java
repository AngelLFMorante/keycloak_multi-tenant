package com.example.keycloak.multitenant.service.utils;

import com.example.keycloak.multitenant.config.KeycloakProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Servicio de configuración para resolver y mapear nombres de tenants a realms de Keycloak,
 * y para obtener la clave pública de un realm.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Service
public class KeycloakConfigService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakConfigService.class);
    private static final String OIDC_ENDPOINT = "/.well-known/openid-configuration";

    private final KeycloakProperties keycloakProperties;
    private final RestTemplate restTemplate = new RestTemplate();
    private final Map<String, Key> publicKeyCache = new ConcurrentHashMap<>();

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param keycloakProperties Las propiedades de configuración de Keycloak.
     */
    public KeycloakConfigService(KeycloakProperties keycloakProperties) {
        this.keycloakProperties = keycloakProperties;
    }

    /**
     * Valida y resuelve el realm interno de Keycloak a partir del nombre público del tenant.
     *
     * @param realm El nombre del tenant (ej. 'plexus').
     * @return El nombre del realm interno de Keycloak (ej. 'plexus-realm').
     * @throws ResponseStatusException Si no se encuentra un mapeo para el realm dado.
     */
    public String resolveRealm(String realm) {
        log.info("Resolviendo el realm público '{}'", realm);
        String keycloakRealm = keycloakProperties.getRealmMapping().get(realm);
        if (keycloakRealm == null) {
            log.warn("Mapeo no encontrado para realm '{}'", realm);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Realm " + realm + " no reconocido");
        }
        log.debug("Realm '{}' mapeado a '{}'", realm, keycloakRealm);
        return keycloakRealm;
    }

    /**
     * Obtiene la clave pública de un realm de Keycloak para verificar firmas de tokens.
     * La clave se almacena en caché para evitar peticiones repetidas.
     *
     * @param realm El nombre del tenant (ej. 'plexus').
     * @return La clave pública del realm.
     * @throws ResponseStatusException Si la clave no puede ser obtenida o es inválida.
     */
    public Key getRealmPublicKey(String realm) {
        log.info("Obteniendo clave pública para el realm: '{}'", realm);
        return publicKeyCache.computeIfAbsent(realm, key -> {
            try {
                String keycloakRealm = resolveRealm(realm);
                String oidcUrl = keycloakProperties.getAuthServerUrl() + "/realms/" + keycloakRealm + OIDC_ENDPOINT;
                log.debug("URL de configuración OIDC: {}", oidcUrl);

                // Obtener el JWKS URL del endpoint OIDC
                Map<String, Object> oidcConfig = restTemplate.getForObject(oidcUrl, Map.class);
                String jwksUrl = (String) oidcConfig.get("jwks_uri");
                log.debug("URL del JWKS: {}", jwksUrl);

                // Descargar el JWKS
                Map<String, Object> jwks = restTemplate.getForObject(jwksUrl, Map.class);

                @SuppressWarnings("unchecked")
                List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");

                if (keys == null || keys.isEmpty()) {
                    log.error("No se encontraron claves de firma en el JWKS para el realm '{}'", realm);
                    throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se encontró una clave de firma para el realm.");
                }

                // Encontrar la clave de firma (use: "sig")
                Map<String, Object> signingKeyData = keys.stream()
                        .filter(k -> "sig".equals(k.get("use")))
                        .findFirst()
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se encontró una clave de firma válida en el JWKS."));

                // Obtener el módulo (n) y el exponente (e) de la clave
                String nStr = (String) signingKeyData.get("n");
                String eStr = (String) signingKeyData.get("e");

                // Decodificar Base64Url y construir la clave pública RSA
                byte[] nBytes = Base64.getUrlDecoder().decode(nStr);
                byte[] eBytes = Base64.getUrlDecoder().decode(eStr);
                BigInteger modulus = new BigInteger(1, nBytes);
                BigInteger publicExponent = new BigInteger(1, eBytes);

                RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                return keyFactory.generatePublic(publicKeySpec);

            } catch (Exception e) {
                log.error("Error al obtener la clave pública para el realm '{}': {}", realm, e.getMessage(), e);
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error al obtener la clave pública para el realm: " + realm, e);
            }
        });
    }
}
