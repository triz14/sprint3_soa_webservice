package br.com.rivaia.auth.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import br.com.rivaia.auth.user.Role;
import br.com.rivaia.auth.user.UserService;

/**
 * Garante que exista um ADMIN para gerenciar usuários. Sem ele, ninguém
 * conseguiria usar os endpoints administrativos, já que o cadastro público
 * sempre cria perfis USER.
 */
@Component
public class AdminSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminSeeder.class);

    private final AdminProperties admin;
    private final UserService userService;

    public AdminSeeder(AdminProperties admin, UserService userService) {
        this.admin = admin;
        this.userService = userService;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (userService.emailExists(admin.email())) {
            return;
        }
        userService.create(admin.name(), admin.email(), admin.password(), Role.ADMIN);
        log.info("Administrador inicial criado: {}", admin.email());
    }
}
