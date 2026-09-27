package br.com.rivaia.auth.common.error;

import org.springframework.http.HttpStatus;

/**
 * Exceção de domínio que já carrega o status HTTP correspondente.
 * As subclasses deixam claro no código qual erro está sendo sinalizado.
 */
public abstract class ApiException extends RuntimeException {

    private final HttpStatus status;
    private final String title;

    protected ApiException(HttpStatus status, String title, String detail) {
        super(detail);
        this.status = status;
        this.title = title;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getTitle() {
        return title;
    }
}
