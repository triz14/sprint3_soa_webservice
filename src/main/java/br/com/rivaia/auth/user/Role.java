package br.com.rivaia.auth.user;

/**
 * Perfis de acesso.
 * <ul>
 *   <li>ADMIN: gerencia cadastro, atualização e remoção de usuários.</li>
 *   <li>USER: usuário do app RivaIA; acessa apenas o próprio perfil.</li>
 * </ul>
 */
public enum Role {
    ADMIN,
    USER
}
