package gaddam1987.github.auth.config;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Message {
    private final String message;
    private final String digest;
    private final String signature;

    public Message(String message, String digest, String signature) {
        this.message = message;
        this.digest = digest;
        this.signature = signature;
    }
}
