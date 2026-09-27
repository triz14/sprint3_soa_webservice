package br.com.rivaia.auth.config;

import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;

@Configuration
@OpenAPIDefinition(info = @Info(
        title = "RivaIA Auth Service",
        version = "1.0.0",
        description = """
                Microsserviço de identidade da RivaIA. Cadastra usuários, autentica \
                e emite tokens JWT (RS256) que os demais serviços da solução validam \
                pela chave pública publicada em /.well-known/jwks.json."""))
@SecurityScheme(
        name = OpenApiConfig.BEARER,
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT")
public class OpenApiConfig {

    public static final String BEARER = "bearerAuth";
}
