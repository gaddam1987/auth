package gaddam1987.github.auth.config.util;

public class SignatureVerifyingException extends AuthenticationException {
    SignatureVerifyingException(String s, Throwable cause) {
        super(s, cause);
    }

    SignatureVerifyingException(String message) {
        super(message);
    }
}
