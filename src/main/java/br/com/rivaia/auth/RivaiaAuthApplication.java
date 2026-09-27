package br.com.rivaia.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class RivaiaAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(RivaiaAuthApplication.class, args);
    }
}
