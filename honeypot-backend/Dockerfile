# ─────────────────────────────────────────────────────────────
# Stage 1: Build the JAR using Maven + JDK 17
# ─────────────────────────────────────────────────────────────
FROM maven:3.9.6-eclipse-temurin-17-alpine AS build

WORKDIR /app

# Copy pom.xml first so Maven can download dependencies.
# This layer is cached — if pom.xml doesn't change, Maven
# won't re-download anything on the next build (much faster).
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Now copy the source code and build the JAR
COPY src ./src
RUN mvn clean package -DskipTests

# ─────────────────────────────────────────────────────────────
# Stage 2: Run — use a smaller JRE-only image (no Maven needed)
# ─────────────────────────────────────────────────────────────
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

# Copy only the built JAR from Stage 1
COPY --from=build /app/target/dashboard-0.0.1-SNAPSHOT.jar app.jar

# Render sets $PORT automatically — Spring Boot reads it via server.port=${PORT:8080}
EXPOSE 8080

# Start the app in production mode
ENTRYPOINT ["java", \
            "-Dspring.profiles.active=prod", \
            "-Xms256m", \
            "-Xmx400m", \
            "-jar", \
            "app.jar"]
