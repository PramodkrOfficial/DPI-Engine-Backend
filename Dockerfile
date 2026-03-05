# -------- Stage 1: Build the application --------
FROM maven:3.9.9-eclipse-temurin-21 AS builder

WORKDIR /build

# Copy project files
COPY pom.xml .
COPY src ./src

# Build the Spring Boot jar
RUN mvn clean package -DskipTests


# -------- Stage 2: Run the application --------
FROM eclipse-temurin:21-jdk-jammy

WORKDIR /app

# Copy jar from build stage
COPY --from=builder /build/target/*.jar dpi-engine.jar

# Expose Spring Boot port
EXPOSE 8080

# Healthcheck (uses your /health endpoint)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
CMD curl -f http://localhost:8080/health || exit 1

# Run the application
ENTRYPOINT ["java","-jar","dpi-engine.jar"]