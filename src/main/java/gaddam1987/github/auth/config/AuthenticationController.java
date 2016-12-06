package gaddam1987.github.auth.config;

import gaddam1987.github.auth.config.util.AuthenticationException;
import gaddam1987.github.auth.config.util.RSASHA1SignatureUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;

import static com.google.common.collect.Lists.newArrayList;
import static java.lang.String.format;
import static org.springframework.util.StringUtils.isEmpty;

@Controller
@RequestMapping("/**")
@Slf4j
public class AuthenticationController {

    private final String X_CONTENT_DIGEST = "X-Content-Digest";
    private final String X_SIGNATURE = "X-Signature";
    ;
    private final RSASHA1SignatureUtil rsasha1SignatureUtil;

    private final RestTemplate restTemplate;
    private RSAPubKeyReader rsaKeyReader;


    @Autowired
    public AuthenticationController(RSASHA1SignatureUtil rsasha1SignatureUtil,
                                    RestTemplate restTemplate,
                                    RSAPubKeyReader rsaKeyReader) {
        this.rsasha1SignatureUtil = rsasha1SignatureUtil;
        this.restTemplate = restTemplate;
        this.rsaKeyReader = rsaKeyReader;
    }

    @RequestMapping
    public ResponseEntity<?> handle(HttpEntity<String> httpEntity, HttpServletRequest request) throws IOException {
        HttpHeaders headers = httpEntity.getHeaders();

        assertBody(httpEntity);
        assertHeaderNotEmpty(httpEntity, X_CONTENT_DIGEST);
        assertHeaderNotEmpty(httpEntity, X_SIGNATURE);


        rsasha1SignatureUtil.verify(new Message(httpEntity.getBody(), headers.get(X_CONTENT_DIGEST).get(0), headers.get(X_SIGNATURE).get(0)),
                rsaKeyReader.getPublicKey());
        RequestEntity<String> requestEntity = new RequestEntity<>(httpEntity.getBody(),
                headers,
                HttpMethod.resolve(request.getMethod()),
                URI.create(format("http://hello/%s", request.getRequestURI())));

        try {
            ResponseEntity<String> exchange = restTemplate.exchange(requestEntity, String.class);

            /**
             * Sign the response
             */
            String responseMessage = exchange.getBody();

            Message signedMessage = rsasha1SignatureUtil.sign(responseMessage, rsaKeyReader.getPrivateKey());

            HttpHeaders responseHeaders = new HttpHeaders();

            responseHeaders.putAll(exchange.getHeaders());
            responseHeaders.put(X_CONTENT_DIGEST, newArrayList(signedMessage.getDigest()));
            responseHeaders.put(X_SIGNATURE, newArrayList(signedMessage.getSignature()));


            return new ResponseEntity<Object>(signedMessage.getMessage(),
                    responseHeaders,
                    HttpStatus.valueOf(exchange.getStatusCodeValue()));
        } catch (Exception e) {
            log.warn("Application Failed to respond with bla bla...", e);
            throw new RuntimeException("Some shit happened while authenticating", e);
        }

    }

    private void assertHeaderNotEmpty(HttpEntity<String> httpEntity, String headerName) {
        if (isEmpty(httpEntity.getHeaders().get(headerName))) {
            throw new AuthenticationException(format("Empty header %s expected some value", headerName));
        }
    }

    private void assertBody(HttpEntity<String> httpEntity) {
        if (httpEntity.getBody() == null) {
            throw new AuthenticationException("Empty body cant be signed and authenticated");
        }
    }

    @Component
    public static class AuthenticationService {

        public void verifySig() {

        }

        private RequestEntity<Object> createRequestEntity() {
            return null;
        }

        private void addCustomHeaders(HttpServletResponse response, ResponseEntity responseEntity) {
            String contentDigest = createContentDigest(responseEntity);

            addContentDigestHeader(response, contentDigest);

            addSignature(contentDigest, response);
        }

        private String createContentDigest(ResponseEntity responseEntity) {
            return null;
        }

        private void addContentDigestHeader(HttpServletResponse response, String contentDigest) {
        }

        private void addSignature(String contentDigest, HttpServletResponse response) {
        }
    }
}
