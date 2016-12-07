package gaddam1987.github.auth.config.util;

public class AuthenticationException extends RuntimeException {

    AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }

    public AuthenticationException(String message) {
        super(message);
    }
}
