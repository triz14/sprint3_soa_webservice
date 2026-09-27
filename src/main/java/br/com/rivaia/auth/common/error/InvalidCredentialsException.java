package br.com.rivaia.auth.common.error;

import org.springframework.http.HttpStatus;

public class InvalidCredentialsException extends ApiException {

    public InvalidCredentialsException(String detail) {
        super(HttpStatus.UNAUTHORIZED, "Não autenticado", detail);
    }
}
