[![Java](https://img.shields.io/badge/Java-17-007396?style=flat\&logo=java\&logoColor=white)](https://www.java.com/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-3-6DB33F?style=flat\&logo=spring-boot\&logoColor=white)](https://spring.io/projects/spring-boot)
[![Keycloak](https://img.shields.io/badge/Keycloak-22+-7C3AED?style=flat\&logo=keycloak\&logoColor=white)](https://www.keycloak.org/)
[![Postman](https://img.shields.io/badge/Postman-FF6C37?style=flat\&logo=postman\&logoColor=white)](https://www.postman.com/)
[![Swagger](https://img.shields.io/badge/Swagger-3-85EA2D?style=flat\&logo=swagger)](https://swagger.io/)
[![Docker](https://img.shields.io/badge/Docker-Container_Ready-2496ED?style=flat\&logo=docker\&logoColor=white)](https://www.docker.com/)

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
* **SLF4J + Logback** para logs
* **Swagger/OpenAPI** para documentación REST

## 🚀 Cómo Ejecutar el Proyecto

### 1. Clonar el Repositorio

```bash
  git clone https://github.com/AngelLFMorante/keycloak_multi-tenant
  cd tu-repo
```

### 2. Levantar Keycloak con Docker (modo desarrollo y persistencia)

```bash
    docker run -p 8080:8080 \
    -e KEYCLOAK_ADMIN=admin \
    -e KEYCLOAK_ADMIN_PASSWORD=admin \
    -v keycloak_data:/opt/keycloak/data \
    quay.io/keycloak/keycloak:latest start-dev
```

Esto levantará Keycloak en [http://localhost:8080](http://localhost:8080) con persistencia de datos gracias al volumen
keycloak\_data.

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

## 🔐 Endpoints Disponibles

| Método | Endpoint                            | Descripción                     |
|--------|-------------------------------------|---------------------------------|
| GET    | `/api/v1/{realm}/login`             | Página de login                 |
| POST   | `/api/v1/{realm}/{client}/do_login` | Login con usuario/password      |
| GET    | `/api/v1/{realm}/users`             | Obtener todos los usuarios      |
| POST   | `/api/v1/{realm}/users/register`    | Registro de usuario en Keycloak |
| PUT    | `/api/v1/{realm}/users/{userId}`    | Actualizar un usuario           |
| DELETE | `/api/v1/{realm}/users/{userId}`    | Eliminar un usuario             |
| GET    | `/api/v1/logout`                    | Logout y cierre de sesión       |
| GET    | `/api/v1/{realm}/roles`             | Obtener todos los roles         |
| POST   | `/api/v1/{realm}/roles`             | Crear un nuevo rol              |
| DELETE | `/api/v1/{realm}/roles/{roleName}`  | Eliminar un rol específico      |
| GET    | `/swagger-ui/index.html`            | Acceso a Swagger UI             |

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

## 🫰 Manejo de Errores

* `ResourceAccessException` → errores de red
* `HttpClientErrorException` / `HttpServerErrorException` → errores HTTP
* Validaciones (`@Valid`) y errores personalizados
* Excepciones generales y de Keycloak (duplicados, estados inválidos)

## 🔐 Seguridad de la Aplicación

* Login multi-realm
* Logout bidireccional (Keycloak + backend)
* Máxima 1 sesión activa por usuario
* Rutas públicas permitidas: `/public`, `/swagger-ui`, `/v3/api-docs/**`
* Password dummy no valida credenciales reales

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

## ✅ Pruebas Unitarias

Ejecuta:

```bash
  mvn test
```

## 👤 Autor

**Angel L. Fernandez Morante**

## 📜 Licencia

MIT
