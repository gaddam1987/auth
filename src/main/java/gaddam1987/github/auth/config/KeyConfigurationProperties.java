package gaddam1987.github.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@ConfigurationProperties(prefix = "keys")
@Setter
@Getter
@Component
public class KeyConfigurationProperties {
    private String privateKeyLocation;
    private String publicKeyLocation;
}
