package me.rightsflow.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableDiscoveryClient
@EnableScheduling
@RequiredArgsConstructor
public class RfAuthSvcApplication {

    public static void main(String[] args) {
        SpringApplication.run(RfAuthSvcApplication.class, args);
    }

}