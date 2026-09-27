package br.com.rivaia.auth.common.error;

import org.springframework.http.HttpStatus;

public class BusinessRuleException extends ApiException {

    public BusinessRuleException(String detail) {
        super(HttpStatus.BAD_REQUEST, "Requisição inválida", detail);
    }
}
