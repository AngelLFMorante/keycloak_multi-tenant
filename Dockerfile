# openjdk:17-jdk-slim es una imagen ligera que incluye Java Development Kit (JDK)
FROM maven:3-openjdk-17-slim AS builder

# Establecer el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar el archivo pom.xml para descargar las dependencias primero
COPY pom.xml .

# Descargar las dependencias para que no se descarguen cada vez que cambia el código fuente
RUN mvn dependency:go-offline -B

# Copiar el código fuente del proyecto
COPY src ./src

# Construir el JAR de la aplicación
# '-DskipTests' para saltar las pruebas durante la construcción del JAR dentro del contenedor Docker
RUN mvn package -DskipTests

# openjdk:17-jre-slim es aún más ligera, ya que solo incluye Java Runtime Environment (JRE)
FROM openjdk:17-slim

# Establecer el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar el JAR compilado de la etapa 'builder'
COPY --from=builder /app/target/keycloak-multitenant-0.0.1-SNAPSHOT.jar app.jar

# Exponer el puerto en el que la aplicación Spring Boot escuchará
# este puerto tiene que coincidir con 'server.port' de application.properties
EXPOSE 8081

# Comando para ejecutar la aplicación Spring Boot
# Argumentos opcionales para la JVM por si se necesitan
ENTRYPOINT ["java", "-jar", "app.jar"]


