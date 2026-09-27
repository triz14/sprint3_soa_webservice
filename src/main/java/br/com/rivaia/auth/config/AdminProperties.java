package br.com.rivaia.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Credenciais do administrador inicial, criado na primeira subida do serviço.
 */
@ConfigurationProperties(prefix = "app.admin")
public record AdminProperties(String name, String email, String password) {
}
