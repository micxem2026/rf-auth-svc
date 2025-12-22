ARG GITLAB
FROM amazoncorretto:17.0.13-al2023-headful as builder

WORKDIR /src
COPY . .
# Копируем кеш Gradle wrapper дистрибутива
COPY --chown=root:root .gradle /root/.gradle

SHELL ["/bin/bash", "-c"]

# Установка xargs
RUN dnf install -y findutils
# Собираем проект
RUN chmod +x ./gradlew && ./gradlew --no-daemon assemble

FROM ${GITLAB}/rights-flow/rf-base-images/liberica-openjdk:17.0.13-cds
COPY --from=builder /src/build/libs/rf-auth-svc.jar rf-auth-svc.jar
ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-Xms256m", "-Xmx512m", "-jar","/rf-auth-svc.jar"]