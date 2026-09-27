package br.com.rivaia.auth.common.error;

import org.springframework.http.HttpStatus;

public class AccountDisabledException extends ApiException {

    public AccountDisabledException(String detail) {
        super(HttpStatus.FORBIDDEN, "Acesso negado", detail);
    }
}
