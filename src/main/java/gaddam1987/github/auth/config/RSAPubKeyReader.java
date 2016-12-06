package gaddam1987.github.auth.config;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Component
@Slf4j
public class RSAPubKeyReader {

    @Value("${keys.private.key.location}")
    String privateKeyLocation;

    @Value("${keys.public.key.location}")
    String publicKeyLocation;


    public PrivateKey getPrivateKey() {
        Resource resource = new ClassPathResource(privateKeyLocation);
        try (BufferedReader k = new BufferedReader(new FileReader(resource.getURL().getPath()))) {
            PemReader pemReader = new PemReader(new BufferedReader(k));
            PemObject pemObject = pemReader.readPemObject();
            KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
            return factory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to retrieve public key", e);
        }
    }

    public PublicKey getPublicKey() throws IOException {
        Resource resource = new ClassPathResource(publicKeyLocation);
        try (BufferedReader k = new BufferedReader(new FileReader(resource.getURL().getPath()))) {
            PemReader pemReader = new PemReader(new BufferedReader(k));
            PemObject pemObject = pemReader.readPemObject();
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pemObject.getContent());
            KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
            return factory.generatePublic(x509EncodedKeySpec);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to retrieve private key", e);
        }
    }
}
