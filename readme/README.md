# Integración de Spring Security y Keycloak (Password Grant Type)

Este proyecto demuestra cómo integrar Spring Security con Keycloak utilizando el flujo de **Password Grant Type**. Esto permite que una aplicación backend autentique usuarios directamente contra Keycloak, obteniendo sus tokens y roles, y luego establezca una sesión de Spring Security para manejar la autorización dentro de la aplicación.

## Cambios Principales Implementados

Hemos realizado modificaciones clave en las clases **SecurityConfig.java** y **LoginController.java** para lograr esta integración:

### 1. LoginController.java

- **Autenticación con Keycloak:** El controlador ahora se encarga de realizar la llamada directa a Keycloak (endpoint `/protocol/openid-connect/token`) usando `RestTemplate` para el **Password Grant Type**. Envía el `username` y `password` proporcionados por el usuario para obtener un `access_token` y un `id_token`.

- **Extracción de Roles:** Una vez obtenidos los tokens de Keycloak, se utiliza la librería `auth0-jwt` para decodificar el `access_token` y extraer los roles del usuario desde las claims `realm_access` y `resource_access` (específicamente para el cliente `mi-app-{realm}`). Estos roles se convierten a objetos `SimpleGrantedAuthority` (prefijados con `ROLE_`) para ser utilizados por Spring Security.

- **Autenticación Dummy en Spring Security:** Para que Spring Security reconozca al usuario como autenticado y cree una sesión, se realiza una autenticación "dummy" con el `AuthenticationManager` de Spring Security. Esto se hace con el `preferredUsername` de Keycloak y una `dummy_password` predefinida. La autenticación real de la contraseña ya la hizo Keycloak.

- **Establecimiento del SecurityContext:** Se crea un `UsernamePasswordAuthenticationToken` final que incluye el principal (usuario) autenticado por el `AuthenticationManager` y las autoridades (roles) reales obtenidas de Keycloak. Este token se establece en el `SecurityContextHolder`.

- **Persistencia de la Sesión:** Se inyecta y utiliza `SecurityContextRepository` para guardar explícitamente el `SecurityContext` en la `HttpSession`. Esto asegura que la sesión de Spring Security persista la autenticación del usuario a través de las redirecciones y las peticiones subsiguientes.

- **Manejo de Éxito y Error de Redirección:**

    - **Éxito:** En caso de éxito, el `AuthenticationSuccessHandler` (configurado en `SecurityConfig`) se encarga de redirigir al usuario a la página de inicio (`/plexus/home`). El método `doLogin` ahora es `void` y no devuelve una `String` de redirección para evitar conflictos de doble redirección.

    - **Error:** En caso de fallo (errores de Keycloak, credenciales incorrectas, etc.), el controlador captura las excepciones y utiliza `HttpServletResponse.sendRedirect()` para redirigir al usuario de vuelta a la página de login (`/login?error=true&tenantId=...`), mostrando mensajes de error adecuados.

### 2. SecurityConfig.java

- **AuthenticationManager Personalizado:** Se ha definido un `@Bean` para `AuthenticationManager` que utiliza un `DaoAuthenticationProvider`. Este proveedor se configura con un `UserDetailsService` y un `PasswordEncoder` "dummy".

- **UserDetailsService Dummy:** Se ha creado un `@Bean` para `UserDetailsService` que siempre devuelve un `User` con el `username` proporcionado y la `DUMMY_PASSWORD` (definida como constante `public static final` en esta clase). Este servicio no valida la contraseña, ya que la validación real la hace Keycloak. Su propósito es solo satisfacer la dependencia del `DaoAuthenticationProvider`.

- **PasswordEncoder No-Op:** Se ha configurado un `NoOpPasswordEncoder.getInstance()` como `@Bean` para `PasswordEncoder`. Este codificador no realiza ninguna operación de cifrado/descifrado de contraseñas, lo cual es esencial para que la `dummy_password` coincida con la que espera el `UserDetailsService` dummy. **¡Advertencia: No usar en producción para contraseñas reales!**

- **AuthenticationSuccessHandler:** Se ha definido un `SimpleUrlAuthenticationSuccessHandler` como `@Bean` para manejar la redirección exitosa después de que Spring Security registra la autenticación. Se configura para redirigir a `/plexus/home`.

- **SecurityContextRepository:** Se ha expuesto `HttpSessionSecurityContextRepository` como un `@Bean` para permitir su inyección y uso explícito en `LoginController`, garantizando la persistencia del contexto de seguridad en la sesión HTTP.

- **Reglas de Autorización:** Se han ajustado las reglas en `securityFilterChain` para permitir el acceso público a las rutas de login (`/{realm}/login`, `/{realm}/do_login`) y proteger otras rutas (`/{realm}/**`) para usuarios autenticados.

## Para un Futuro Menos Hardcodeado y Más Robusto

La implementación actual contiene algunos elementos que están **hardcodeados** o simplificados para facilitar la puesta en marcha. Para un entorno de producción o una solución más flexible, deberías considerar los siguientes cambios:

### Constantes en Archivos de Propiedades

- **DUMMY_PASSWORD:** Actualmente es una constante `public static final` en `SecurityConfig.java`. Idealmente, esta "contraseña" dummy no debería ser accesible fuera de la configuración. Una mejor práctica sería que el `UserDetailsService` genere una contraseña aleatoria y la compare con esa misma aleatoria, o que simplemente no realice ninguna comparación de contraseña y confíe ciegamente en que Keycloak ya validó al usuario. Sin embargo, si necesitas que sea una cadena fija, podrías moverla a `application.properties` y cargarla con `@Value` en ambos lugares, asegurando que coincida.

- **KEYCLOAK_AUTHORITY_PREFIX:** `ROLE_` es un prefijo estándar de Spring Security. Puedes mantenerlo como constante si es solo para tu aplicación.

### URLs de Redirección Post-Login

Actualmente, el `AuthenticationSuccessHandler` redirige incondicionalmente a `/plexus/home`. Para una aplicación multi-tenant, querrías que la redirección fuera dinámica (ej. `/ {realm}/home`).

Para lograr esto, podrías:

- **Crear un AuthenticationSuccessHandler personalizado:** Que extienda `SimpleUrlAuthenticationSuccessHandler` y sobrescriba el método `determineTargetUrl()` para construir la URL de redirección basándose en el `realm` o cualquier otro atributo del usuario autenticado que pudieras guardar en el `Authentication` o la sesión.

- **Pasar el realm como parámetro:** Al llamar al `AuthenticationSuccessHandler`, podrías añadir el `realm` a la sesión y que el handler lo lea.

### Manejo de Roles y Autorizaciones Más Flexibles

Las reglas de autorización como `.hasRole("USER_APP")` son estáticas. Si los roles de Keycloak son muy dinámicos o provienen de diferentes fuentes, podrías necesitar una lógica de mapeo de roles más sofisticada, quizás un `GrantedAuthoritiesMapper` si también usas **OAuth2 Login**.

Considera el uso de anotaciones de seguridad (`@PreAuthorize`, `@PostAuthorize`) en tus métodos de servicio o controlador para un control de acceso más granular.

### Gestión de Sesiones (Timeout, Invalidez)

Revisa y ajusta la configuración de `sessionManagement` en `SecurityConfig` según tus necesidades de seguridad y experiencia de usuario (tiempos de inactividad, invalidación de sesiones, etc.).

### Flujo OAuth2 Login (Authorization Code Flow)

Si tu aplicación requiere un flujo más seguro y completo (como el inicio de sesión vía interfaz de Keycloak en el navegador en lugar de enviar credenciales directamente desde tu aplicación), deberías habilitar y configurar el `.oauth2Login()` en tu `SecurityFilterChain`. Esto es lo recomendado por **OAuth2/OpenID Connect** para la mayoría de las aplicaciones cliente. Las partes de `ClientRegistrationRepository` y `oidcUserService()` ya están presentes en tu `SecurityConfig` para esto.

### Errores y Mensajes al Usuario

Los mensajes de error mostrados al usuario (`model.addAttribute("error", ...)`) son bastante genéricos. En un entorno real, querrías mensajes más amigables y específicos, y quizás una interfaz de usuario más pulida para mostrar esos errores.

### Logging y Monitoreo

Asegúrate de tener un logging adecuado para la depuración y el monitoreo en producción. Los `System.out.println` deben ser reemplazados por un logger (slf4j, log4j, etc.).
