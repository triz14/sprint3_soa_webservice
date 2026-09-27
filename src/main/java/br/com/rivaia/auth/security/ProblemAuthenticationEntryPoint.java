package br.com.rivaia.auth.security;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import br.com.rivaia.auth.common.error.ApiError;

/**
 * Resposta 401 quando o token está ausente, malformado, com assinatura
 * inválida, de outro emissor ou expirado.
 */
@Component
public class ProblemAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException ex) throws IOException {
        boolean invalidToken = ex instanceof InvalidBearerTokenException;
        String detail = invalidToken
                ? "Token inválido ou expirado. Faça login novamente."
                : "Autenticação necessária. Envie o header Authorization: Bearer <token>.";
        response.setHeader("WWW-Authenticate", invalidToken
                ? "Bearer error=\"invalid_token\""
                : "Bearer");
        ProblemJsonWriter.write(response,
                ApiError.of(401, "Não autenticado", detail, request.getRequestURI()));
    }
}
