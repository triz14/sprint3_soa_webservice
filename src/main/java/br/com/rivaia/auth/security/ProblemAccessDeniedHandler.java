package br.com.rivaia.auth.security;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import br.com.rivaia.auth.common.error.ApiError;

/**
 * Resposta 403 quando o token é válido, mas o perfil não tem permissão.
 */
@Component
public class ProblemAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException ex) throws IOException {
        ProblemJsonWriter.write(response, ApiError.of(403, "Acesso negado",
                "Seu perfil não tem permissão para acessar este recurso.", request.getRequestURI()));
    }
}
