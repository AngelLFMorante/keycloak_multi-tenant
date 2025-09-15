package com.example.keycloak.multitenant.controller.web;

import com.example.keycloak.multitenant.config.SecurityConfig;
import com.example.keycloak.multitenant.model.LoginResponse;
import com.example.keycloak.multitenant.service.LoginService;
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
 * Controlador web para gestionar login vía formulario Thymeleaf.
 * Usa el mismo LoginService (Password Grant) que el controlador REST.
 */
@Controller
@RequiredArgsConstructor
public class WebAuthController {

    private static final Logger log = LoggerFactory.getLogger(WebAuthController.class);

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final LoginService loginService;

    /**
     * Muestra la página de login para un realm.
     */
    @GetMapping("/{realm}/{client}/login")
    public String showLoginPage(@PathVariable String realm,
                                @PathVariable String client,
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
     */
    @PostMapping("/{realm}/{client}/do_login")
    public String processLogin(@PathVariable String realm,
                               @PathVariable String client,
                               @RequestParam String username,
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
     * Página de inicio tras login (ejemplo).
     */
    @GetMapping("/{realm}/home")
    public String home(@PathVariable String realm, Model model, HttpSession session) {
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
     *
     * @param request La solicitud HTTP para invalidar la sesión.
     * @return Redirecciona a la página de login.
     */
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
