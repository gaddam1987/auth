package gaddam1987.github.auth.config;

import gaddam1987.github.auth.config.util.ExceptionHandlingFilter;
import gaddam1987.github.auth.config.util.RSASHA1SignatureUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.netflix.ribbon.RibbonClient;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

import javax.servlet.Filter;
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

    @Bean
    @Autowired
    public Filter compressFilter(RSASHA1SignatureUtil signatureUtil) {
        return new ExceptionHandlingFilter(signatureUtil);
    }

    public static void main(String[] args) {
        run(AuthConfig.class, args);
    }
}
