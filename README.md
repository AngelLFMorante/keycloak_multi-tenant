[![Java](https://img.shields.io/badge/Java-17-007396?style=flat\&logo=java\&logoColor=white)](https://www.java.com/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-3-6DB33F?style=flat\&logo=spring-boot\&logoColor=white)](https://spring.io/projects/spring-boot)
[![Keycloak](https://img.shields.io/badge/Keycloak-22+-7C3AED?style=flat\&logo=keycloak\&logoColor=white)](https://www.keycloak.org/)
[![Postman](https://img.shields.io/badge/Postman-FF6C37?style=flat\&logo=postman\&logoColor=white)](https://www.postman.com/)
[![Swagger](https://img.shields.io/badge/Swagger-3-85EA2D?style=flat\&logo=swagger)](https://swagger.io/)
[![Docker](https://img.shields.io/badge/Docker-Container_Ready-2496ED?style=flat\&logo=docker\&logoColor=white)](https://www.docker.com/)
[![Thymeleaf](https://img.shields.io/badge/Thymeleaf-E95738?style=flat\&logo=thymeleaf\&logoColor=white)](https://www.thymeleaf.org/)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-7952B3?style=flat\&logo=bootstrap\&logoColor=white)](https://getbootstrap.com/)
---

# Microservicio de Autenticación con Spring Boot y Keycloak

**Microservicio de Autenticación** es una API REST desarrollada con **Spring Boot** que permite gestionar el login de
usuarios mediante Keycloak con soporte multi-realm. Proporciona endpoints para login, logout, registro y gestión de
sesiones, todo centralizado y extensible.

## 📌 Objetivo

* Gestionar usuarios mediante Keycloak Admin Client.
* Permitir login y registro desde múltiples realms.
* Mantener sesiones activas y válidas entre Keycloak y el backend.
* Registrar errores de red, validación, y seguridad de manera estructurada.

## 🛠️ Tecnologías Usadas

* **Java 17**
* **Spring Boot 3.x**
* **Spring Security** con configuración personalizada
* **Keycloak 22+** con clientes confidenciales
* **Keycloak Admin Client SDK**
* **Docker** y **Docker Compose** para orquestación
* **RestTemplate** para comunicación con Keycloak
* **Thymeleaf** para la interfaz web
* **JJWT** para la gestión de tokens en los flujos de email
* **SLF4J + Logback** para logs
* **Swagger/OpenAPI** para documentación REST

## 🚀 Cómo Ejecutar el Proyecto

---

### 1. Clonar el Repositorio

```bash
  git clone https://github.com/AngelLFMorante/keycloak_multi-tenant
  cd tu-repo
```

---

### 2. Levantar Keycloak con Docker (modo desarrollo y persistencia)

El proyecto requiere Keycloak para la gestión de usuarios y MailHog para simular el envío de correos electrónicos en
desarrollo.

```bash
    # Levantar Keycloak en modo de desarrollo
    docker run -p 8080:8080 \
    -e KEYCLOAK_ADMIN=admin \
    -e KEYCLOAK_ADMIN_PASSWORD=admin \
    -v keycloak_data:/opt/keycloak/data \
    quay.io/keycloak/keycloak:latest start-dev

    # Levantar MailHog para probar el envío de emails
    docker run -d -p 1025:1025 -p 8025:8025 --name mailhog mailhog/mailhog
```

Esto levantará Keycloak en [http://localhost:8080](http://localhost:8080) con persistencia de datos gracias al volumen
keycloak\_data y MailHog en http://localhost:8025.

---

### 3. Crear Realm y Configuraciones en Keycloak

Accede a `http://localhost:8080` con:

* **usuario**: `admin`
* **contraseña**: `admin`

Luego:

* Crea un **Realm**: `demo-realm`
* Crea un **Cliente**: `demo-client`
* Agrega URL de redirección: `http://localhost:8081/*`
* Crea **roles**: `user`, `admin`
* Crea un **usuario**: `angel` / `1234`, con rol `user`

### ⚙️ Configuración de `application.properties`

```properties
  keycloak.auth-server-url=http://localhost:8080
keycloak.admin.realm=master
keycloak.admin.username=admin
keycloak.admin.password=admin
keycloak.admin.client-id=admin-cli
```

## ▶️ Ejecutar la Aplicación

```bash
  ./mvnw spring-boot:run
```

O usando Docker:

```bash
  docker build -t spring-auth-service .
  docker run -p 8081:8081 --name keycloak-demo-container keycloak-demo-app
```

---

## 🔐 Endpoints Disponibles

| Método | Endpoint                                                  | Descripción                                  |
|--------|-----------------------------------------------------------|----------------------------------------------|
| GET    | `/api/v1/{realm}/login`                                   | Página de login                              |
| POST   | `/api/v1/{realm}/{client}/do_login`                       | Login con usuario/password                   |
| POST   | `/api/v1/refresh`                                         | Renueva el token de acceso usando            |
| GET    | `/api/v1/{realm}/users`                                   | Obtener todos los usuarios                   |
| POST   | `/api/v1/{realm}/users/register`                          | Registro de usuario en Keycloak              |
| PUT    | `/api/v1/{realm}/users/{userId}`                          | Actualizar un usuario                        |
| DELETE | `/api/v1/{realm}/users/{userId}`                          | Eliminar un usuario                          |
| GET    | `/api/v1/{realm}/users/{userId}`                          | Obterner un usuario por su ID                |
| GET    | `/api/v1/{realm}/users/email/{email}`                     | Obterner un usuario por su email             |
| GET    | `/api/v1/{realm}/users/attributes`                        | Obterner usuarios por filtro atributos       |
| POST   | `/api/v1/{realm}/users/{userId}/password-reset`           | Reestablece password del usuario             |
| GET    | `/api/v1/logout`                                          | Logout y cierre de sesión                    |
| GET    | `/api/v1/{realm}/roles`                                   | Obtener todos los roles                      |
| POST   | `/api/v1/{realm}/roles`                                   | Crear un nuevo rol                           |
| DELETE | `/api/v1/{realm}/roles/{roleName}`                        | Eliminar un rol específico                   |
| GET    | `/api/v1/{realm}/roles/{roleName}/attributes`             | Obtener atributos de un rol                  |
| PUT    | `/api/v1/{realm}/roles/{roleName}/attributes`             | Añadir/Actualizar atributos de un rol        |
| DELETE | `/api/v1/{realm}/roles/{roleName}/attributes`             | Eliminar un atributo de un rol               |
| POST   | `/api/v1/{realm}/auth/{client}/validate`                  | Validar un token de acceso o refresco.       |
| POST   | `/api/v1/{realm}/auth/{client}/token`                     | Obtener un token usando Client Credentials.  |
| POST   | `/api/v1/{realm}/{client}/users/{userId}/change-password` | Cambiar contraseña de usuario                |
| POST   | `/api/v1/realms/create`                                   | Crear un nuevo Realm en Keycloak             |
| POST   | `/api/v1/clients/create`                                  | Crear un nuevo Cliente en un Realm           |
| POST   | `/api/v1/{realm}/password/set`                            | Establece la nueva contraseña de un usuario. |
| POST   | `/api/v1/{realm}/password/verify`                         | Valida un token de verificación de correo.   |
| GET    | `/swagger-ui/index.html`                                  | Acceso a Swagger UI                          |

---

## 🧪 Postman cURL's de Ejemplo

### 🔑 Login

```bash
    curl -X POST http://localhost:8081/api/v1/{REALM_PATH}/{CLIENT_ID}/do_login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username={USERNAME}&password={PASSWORD}'
```

### 🔄 Refresh Token

```bash
  curl -X POST \
http://localhost:8081/api/v1/refresh \
-H 'Content-Type: application/json' \
-d '{
      "refresh_token": "eyJhbG..."
    }'
```

### 🔐 Logout

```bash
  curl -X POST \
http://localhost:8081/api/v1/logout \
-H 'Content-Type: application/json' \
-d '{
      "refresh_token": "eyJhbG..."
    }'
```

### 🧝 Registro usuario

```bash
  curl -X POST \
http://localhost:8081/api/v1/{REALM_PATH}/users/register \
-H 'Content-Type: application/json' \
-d '{
      "username": "newuser",
      "email": "newuser@example.com",
      "firstName": "New",
      "lastName": "User",
      "role": "user"
    }'
```

### 🧝 Obtener todos los usuarios

```bash
  curl -X GET http://localhost:8081/api/v1/{REALM_PATH}/users
```

### 🧝 Actualizar usuario

```bash
  curl -X PUT http://localhost:8081/api/v1/{REALM_PATH}/users/{USER_ID} \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "updated.user@example.com",
    "firstName": "Updated",
    "lastName": "User"
  }'
```

### 🧝 Eliminar usuario

```bash
  curl -X DELETE http://localhost:8081/api/v1/{REALM_PATH}/users/{USER_ID}
```

### 🧝 Obtener usuario por ID

```bash
  curl -X GET http://localhost:8081/api/v1/{REALM_PATH}/users/{USER_ID}
```

### 🧝 Obtener usuario por email

```bash
  curl -X GET http://localhost:8081/api/v1/{REALM_PATH}/users/email/{EMAIL}
```

### 🧝 Obtener usuarios por filtro atritbutos

```bash
  curl -X GET http://localhost:8081/api/v1/{REALM_PATH}/users/attributes?organization=XX&subsidiary=XX&department=XX
```

### 🧝 Reestablecer password de usuario

```bash
  curl --location 'http://localhost:8081/api/v1/{REALM_PATH}/users/{USER_ID}/password-reset' \
       --header 'Authorization: Bearer YOUR_ACCESS_TOKEN' \
       --header 'Content-Type: application/x-www-form-urlencoded' \
       --data-urlencode 'newPassword=87654321'
```

🔑 Cambiar password de usuario

```bash
     curl --location 'http://localhost:8081/api/v1/{REALM_PATH}/{CLIENT_ID}/users/{USER_ID}/change-password' \
          --header 'Content-Type: application/json' \
          --data-raw '{
                "username": "usuario@gmail.com",
                "currentPassword": "currentPassword!1",
                "newPassword": "newSecurePassword!1"
          }'
```

### 📧 Flujo de Verificación y Restablecimiento de Contraseña

🔑 Verificar el email con el token

```bash
    curl -X POST "http://localhost:8081/api/{realm}/password/verify?token={TOKEN}"
```

🔑 Establecer nueva contraseña

```bash
    curl -X POST "http://localhost:8081/api/{realm}/password/set?token={TOKEN}&password={NEW_PASSWORD}"
```

### 🧾 Obtener Roles

```bash
  curl -X GET http://localhost:8081/api/v1/{REALM_PATH}/roles
```

### ➕ Crear Rol

```bash
  curl -X POST \
http://localhost:8081/api/v1/{REALM_PATH}/roles \
-H 'Content-Type: application/json' \
-H 'Authorization: Bearer <access_token>' \
-d '{
      "name": "new_role",
      "description": "A new role created via API"
    }'
```

### ❌ Eliminar Rol

```bash
  curl -X DELETE \
http://localhost:8081/api/v1/{REALM_PATH}/roles/{ROLE_NAME}
```

### ⚙️ Gestión de Atributos de Roles

🧾 Obtener Atributos de Rol

```bash
  curl -X GET http://localhost:8081/api/v1/{REALM_PATH}/roles/{ROLE_NAME}/attributes
```

➕ Añadir/Actualizar Atributos de Rol

```bash
  curl -X PUT http://localhost:8081/api/v1/{REALM_PATH}/roles/{ROLE_NAME}/attributes \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <access_token>' \
  -d '{
      "attribute1": ["value1", "value2"],
      "another_attribute": ["value3"]
    }'
```

❌ Eliminar Atributo de Rol

```bash
  curl -X DELETE http://localhost:8081/api/v1/{REALM_PATH}/roles/{ROLE_NAME}/attributes/{ATTRIBUTE_NAME}
```

### 🔒 Endpoints de Autenticación

📝 Validar Token

```bash
    curl -X POST http://localhost:8081/api/v1/{REALM_PATH}/auth/{CLIENT_ID}/validate \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <access_token_del_cliente_admin>' \
  -d '{
      "token": "eyJhbG..."
    }'
```

🔑 Obtener Token de Cliente

```bash
     curl -X POST http://localhost:8081/api/v1/{REALM_PATH}/auth/{CLIENT_ID}/token \
  -H 'Content-Type: application/json'
```

### ➕ Crear Realms y Clientes

🌐 Crear un nuevo Realm

```bash
     curl -X POST http://localhost:8081/api/v1/realms/create \
          -H "Content-Type: application/json" \
          -d '{
                "realm": "nuevo-realm-de-prueba"
              }'
```

🔑 Crear un nuevo Cliente en un Realm

```bash
     curl -X POST http://localhost:8081/api/v1/clients/create \
          -H "Content-Type: application/json" \
          -d '{
                "realm": "demo-realm",
                "client": "my-new-client"
              }'
```

---

### 🖥️ Interfaz Web con Thymeleaf

Además de los endpoints REST, el microservicio ahora incluye una interfaz de usuario básica desarrollada con Thymeleaf.
Esta interfaz permite a los usuarios interactuar con la aplicación a través de un navegador web, facilitando los flujos
de autenticación y gestión de contraseñas de una manera más intuitiva.

Esta funcionalidad utiliza los mismos servicios y lógica de negocio que los endpoints REST, pero los expone a través de
controladores web dedicados, optimizados para la renderización de vistas.

📝 Flujos y Páginas Disponibles

* Página de Inicio (/): Una página de bienvenida que detecta si el usuario está autenticado y muestra información de su
  sesión. Si no lo está, proporciona enlaces para el login y registro.

* Login Web (/{realm}/{client}/login): Un formulario de login que redirige al usuario para autenticarse usando sus
  credenciales de Keycloak.

* Registro de Usuario (/{realm}/{client}/register): Un formulario para que los nuevos usuarios se registren en un realm
  y cliente específicos.

* Creación de Clientes (/{realm}/clients/create): Una página para crear nuevos clientes en un realm desde la interfaz
  web, ideal para la configuración inicial.

* Flujo de Contraseña (/{realm}/password/...):

    * Verificación (/verify): Un endpoint al que el usuario es redirigido desde el correo de verificación para validar
      un token y acceder al formulario de cambio de contraseña.

    * Establecer Contraseña (/set): Un formulario para que el usuario establezca su nueva contraseña después de haber
      verificado su correo electrónico.

* Página de Inicio de Usuario (/{realm}/home): Muestra un resumen de los datos del usuario autenticado, como su nombre
  de usuario, roles y tokens de acceso.

🌐 Cómo Acceder

Para acceder a la interfaz web, simplemente navega a la URL de tu aplicación en un navegador:

* Página de inicio: http://localhost:8081/

* Página de login: http://localhost:8081/{realm}/{client}/login

* Página de registro: http://localhost:8081/{realm}/{client}/register
*
* Página de creación cliente bajo realm: http://localhost:8081/{realm}/clients/create

---

## 🫰 Manejo de Errores

* `ResourceAccessException` → errores de red
* `HttpClientErrorException` / `HttpServerErrorException` → errores HTTP
* Validaciones (`@Valid`) y errores personalizados
* Excepciones generales y de Keycloak (duplicados, estados inválidos)

---

## 🔐 Seguridad de la Aplicación

* Login multi-realm
* Logout bidireccional (Keycloak + backend)
* Máxima 1 sesión activa por usuario
* Rutas públicas permitidas: `/public`, `/swagger-ui`, `/v3/api-docs/**`
* Password dummy no valida credenciales reales

---

## 🧠 Cómo Funciona la Aplicación

### 🏷️ Multi-tenant: Realms y Clients dinámicos

La aplicación soporta múltiples **realms** y **clients** configurables a través del archivo `application.properties`.
Esto permite enrutar y validar las credenciales de los usuarios contra distintos entornos Keycloak de forma dinámica.

#### 🔁 Realms dinámicos

Se define un mapeo donde el segmento de URL (por ejemplo, `demo`) se asocia a un nombre real del realm en Keycloak:

```properties
keycloak.realm-mapping.plexus=plexus-realm
keycloak.realm-mapping.inditex=inditex-realm
```

Así, una petición a `http://localhost:8081/api/v1/plexus/login` será tratada como perteneciente al realm `plexus-realm`
en Keycloak.

#### 🔑 Clients y Secrets por Realm

Cada realm tiene su propio cliente configurado. En `application.properties`, se declaran los `client-id` y sus
`client-secrets`:

```properties
keycloak.client-secrets.mi-app-plexus=<<secret>>
keycloak.client-secrets.mi-app-inditex=<<secret>>
```

Cuando un usuario intenta hacer login desde un endpoint como:

```
POST /api/v1/plexus/mi-app-plexus/do_login
```

La aplicación busca en `application.properties` el secreto para `mi-app-plexus` y lo utiliza para comunicarse con el
realm `plexus-realm`.

Estas asociaciones deben existir previamente en el archivo de configuración y deben coincidir con los valores reales
configurados en Keycloak.

* Autenticación centralizada mediante Keycloak.
* Gestión de usuarios vía Keycloak Admin Client.
* Configuración de múltiples realms desde `application.properties`.
* Manejo estructurado de excepciones, tokens, sesiones y logout.

---

## ✅ Pruebas Unitarias

Ejecuta:

```bash
  mvn test
```

---

## 👤 Autor

**Angel L. Fernandez Morante**

---

## 📜 Licencia

MIT
