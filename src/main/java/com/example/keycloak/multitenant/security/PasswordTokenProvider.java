package com.example.keycloak.multitenant.security;

import com.example.keycloak.multitenant.config.JwtProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import org.springframework.stereotype.Component;

/**
 * Proveedor de tokens para el flujo de establecimiento de contraseña.
 * <p>
 * Esta clase se encarga de generar y validar tokens JWT de corta duración,
 * que se utilizan para los enlaces de verificación de correo y
 * establecimiento de contraseñas de los usuarios. Utiliza una clave secreta
 * para firmar los tokens, garantizando su integridad y autenticidad.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Component
public class PasswordTokenProvider {

    private final Key key;
    private final long expirationMillis;

    /**
     * Constructor que inicializa el proveedor de tokens con las propiedades de configuración.
     *
     * @param props Las propiedades de JWT, que incluyen el secreto y la expiración.
     */
    public PasswordTokenProvider(JwtProperties props) {
        this.key = Keys.hmacShaKeyFor(props.getSecret().getBytes());
        this.expirationMillis = props.getExpirationHours() * 3600_000;
    }

    /**
     * Genera un token JWT para un usuario con un propósito específico de establecimiento de contraseña.
     * <p>
     * El token incluye la ID del usuario como sujeto, el propósito en un claim, y una fecha de expiración.
     *
     * @param userId El identificador único del usuario para el que se genera el token.
     * @return El token JWT como una cadena de texto.
     */
    public String generateToken(String userId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(userId)
                .claim("purpose", "set-password")
                .setIssuedAt(Date.from(now))
                .setExpiration(new Date(now.toEpochMilli() + expirationMillis))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Valida un token JWT y extrae la ID del usuario.
     * <p>
     * Este método verifica la firma del token, su fecha de expiración y su propósito.
     *
     * @param token El token JWT a validar.
     * @return La ID del usuario si el token es válido.
     * @throws io.jsonwebtoken.JwtException Si el token es inválido, ha expirado o no está bien formado.
     */
    public String validateAndGetUserId(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}
