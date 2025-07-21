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

FROM bellsoft/liberica-openjdk-alpine-musl:17.0.13-cds
RUN apk update && apk add tzdata && apk --no-cache add curl
RUN apk --no-cache add msttcorefonts-installer fontconfig && update-ms-fonts && fc-cache -f
COPY --from=builder /src/build/libs/rf-auth-svc.jar rf-auth-svc.jar
ENV TZ=Europe/Moscow
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-Xms256m", "-Xmx512m", "-jar","/rf-auth-svc.jar"]