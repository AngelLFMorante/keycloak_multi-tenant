package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.config.SecurityConfig;
import com.example.keycloak.multitenant.model.LoginResponse;
import com.example.keycloak.multitenant.service.LoginService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Controlador web para gestionar el flujo de autenticación de usuarios a través de un formulario Thymeleaf.
 * <p>
 * Este controlador maneja la visualización de la página de login, el procesamiento del formulario
 * de autenticación y las operaciones de logout, integrándose con Keycloak y Spring Security.
 *
 * @author Angel Fm
 * @version 1.0
 */
@Controller
@RequiredArgsConstructor
@Tag(name = "Authentication Web", description = "Endpoints web para la gestión de login y logout.")
public class WebAuthController {

    private static final Logger log = LoggerFactory.getLogger(WebAuthController.class);

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final LoginService loginService;

    /**
     * Muestra la página de login para un realm y cliente específicos.
     *
     * @param realm  El nombre del realm (tenant).
     * @param client El ID del cliente de Keycloak.
     * @param error  Parámetro opcional para mostrar un mensaje de error si el login falla.
     * @param model  El modelo de Spring para pasar datos a la vista.
     * @return El nombre de la vista ("login") a renderizar.
     */
    @Operation(
            summary = "Muestra la página de login web.",
            description = "Renderiza la página de login para un realm y cliente dados."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Página de login renderizada exitosamente.")
    })
    @GetMapping("/{realm}/{client}/login")
    public String showLoginPage(
            @Parameter(description = "El identificador del tenant (realm).", required = true)
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente de Keycloak.", required = true)
            @PathVariable String client,
            @Parameter(description = "Mensaje de error opcional.", required = false)
            @RequestParam(value = "error", required = false) String error,
            Model model) {
        model.addAttribute("tenantId", realm);
        model.addAttribute("clientId", client);
        if (error != null) {
            model.addAttribute("error", error);
        }
        return "login";
    }

    /**
     * Procesa el envío del formulario de login.
     * <p>
     * Se autentica contra Keycloak y, si es exitoso, establece la sesión de Spring Security
     * y redirige a la página de inicio.
     *
     * @param realm    El nombre del realm (tenant).
     * @param client   El ID del cliente de Keycloak.
     * @param username El nombre de usuario.
     * @param password La contraseña.
     * @param request  La solicitud HTTP, usada para guardar el contexto de seguridad en la sesión.
     * @param response La respuesta HTTP.
     * @param model    El modelo de Spring.
     * @return Un string de redirección a la página de inicio si el login es exitoso, o a la página de login con un error en caso contrario.
     */
    @Operation(
            summary = "Procesa el login web del usuario.",
            description = "Autentica al usuario usando Password Grant en Keycloak y establece la sesión de Spring Security."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirección a la página de inicio en caso de éxito."),
            @ApiResponse(responseCode = "200", description = "Renderiza la página de login con un error en caso de fallo.")
    })
    @PostMapping("/{realm}/{client}/do_login")
    public String processLogin(
            @Parameter(description = "El identificador del tenant (realm).", required = true)
            @PathVariable String realm,
            @Parameter(description = "El ID del cliente de Keycloak.", required = true)
            @PathVariable String client,
            @Parameter(description = "El nombre de usuario para el login.", required = true)
            @RequestParam String username,
            @Parameter(description = "La contraseña del usuario.", required = true)
            @RequestParam String password,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {
        try {
            log.info("Login web para usuario '{}' en realm '{}'", username, realm);

            // Lógica existente: autenticarse contra Keycloak
            LoginResponse loginResponse = loginService.authenticate(realm, client, username, password);

            // Crear Authentication para Spring Security
            UsernamePasswordAuthenticationToken authRequest =
                    new UsernamePasswordAuthenticationToken(
                            loginResponse.getPreferredUsername(),
                            SecurityConfig.DUMMY_PASSWORD,
                            loginResponse.getRoles().stream()
                                    .map(SimpleGrantedAuthority::new)
                                    .toList()
                    );

            Authentication authentication = authenticationManager.authenticate(authRequest);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            SecurityContext sc = SecurityContextHolder.getContext();
            securityContextRepository.saveContext(sc, request, response);

            // Guardar realm y client en sesión
            HttpSession session = request.getSession(true);
            session.setAttribute("realm", realm);
            session.setAttribute("client", client);
            session.setAttribute("loginResponse", loginResponse);

            log.info("Login web exitoso para '{}'", loginResponse.getPreferredUsername());
            return "redirect:/" + realm + "/home";

        } catch (Exception ex) {
            log.error("Error al autenticar usuario '{}' en realm '{}': {}", username, realm, ex.getMessage());
            model.addAttribute("tenantId", realm);
            model.addAttribute("clientId", client);
            model.addAttribute("error", "Usuario o contraseña incorrectos");
            return "login";
        }
    }

    /**
     * Muestra la página de inicio para un realm, accesible después de un login exitoso.
     *
     * @param realm   El nombre del realm (tenant).
     * @param model   El modelo de Spring.
     * @param session La sesión HTTP para recuperar los datos del usuario.
     * @return El nombre de la vista ("home") a renderizar.
     */
    @Operation(
            summary = "Muestra la página de inicio.",
            description = "Página de bienvenida para usuarios autenticados."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Página de inicio renderizada exitosamente.")
    })
    @GetMapping("/{realm}/home")
    public String home(
            @Parameter(description = "El nombre del realm (tenant).", required = true)
            @PathVariable String realm,
            Model model, HttpSession session) {
        LoginResponse loginResponse = (LoginResponse) session.getAttribute("loginResponse");

        model.addAttribute("realmName", realm);
        if (loginResponse != null) {
            model.addAttribute("message", "Login successful");
            model.addAttribute("username", loginResponse.getUsername());
            model.addAttribute("email", loginResponse.getEmail());
            model.addAttribute("fullName", loginResponse.getFullName());
            model.addAttribute("roles", loginResponse.getRoles());
            model.addAttribute("access_token", loginResponse.getAccessToken());
            model.addAttribute("idToken", loginResponse.getIdToken());
            model.addAttribute("refresh_token", loginResponse.getRefreshToken());
            model.addAttribute("expiresIn", loginResponse.getExpiresIn());
            model.addAttribute("refreshExpiresIn", loginResponse.getRefreshExpiresIn());
            model.addAttribute("realm", loginResponse.getRealm());
            model.addAttribute("client", loginResponse.getClient());
        } else {
            model.addAttribute("username", SecurityContextHolder.getContext().getAuthentication().getName());
        }

        return "home";
    }

    /**
     * Procesa la solicitud POST para cerrar la sesión (logout).
     * <p>
     * Este método revoca el refresh token en Keycloak y invalida la sesión HTTP local.
     *
     * @param request La solicitud HTTP para invalidar la sesión.
     * @return Un string de redirección a la página de login o a la raíz si no hay datos de sesión.
     */
    @Operation(
            summary = "Cierra la sesión del usuario.",
            description = "Revoca el refresh token en Keycloak y invalida la sesión local de Spring Security."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirección a la página de login después del logout.")
    })
    @PostMapping("/logout")
    public String logout(HttpServletRequest request) {
        log.info("Cierre de sesión web iniciado.");
        HttpSession session = request.getSession(false);

        if (session != null) {
            String realm = (String) session.getAttribute("realm");
            String client = (String) session.getAttribute("client");
            LoginResponse loginResponse = (LoginResponse) session.getAttribute("loginResponse");

            if (loginResponse != null && loginResponse.getRefreshToken() != null) {
                log.debug("Revocando refresh token en Keycloak.");
                try {
                    loginService.revokeRefreshToken(loginResponse.getRefreshToken(), realm, client);
                } catch (Exception e) {
                    log.error("Error al revocar el token en Keycloak: {}", e.getMessage());
                }
            }

            session.invalidate();
            log.info("Sesión HTTP invalidada. Redireccionando a la página de login.");
            return "redirect:/" + realm + "/" + client + "/login";
        }

        return "redirect:/";
    }
}
