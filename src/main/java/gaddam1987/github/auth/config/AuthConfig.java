package gaddam1987.github.auth.config;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.netflix.ribbon.RibbonClient;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

import java.security.Security;

import static org.springframework.boot.SpringApplication.run;

@SpringBootApplication
@RibbonClient(name = "hello")
@EnableConfigurationProperties
public class AuthConfig {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @LoadBalanced
    @Bean
    RestTemplate restTemplate() {
        return new RestTemplate();
    }

    public static void main(String[] args) {
        run(AuthConfig.class, args);
    }
}
