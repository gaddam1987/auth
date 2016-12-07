package gaddam1987.github.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import gaddam1987.github.auth.config.util.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
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

    private final RSASHA1SignatureUtil rsasha1SignatureUtil;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;


    @Autowired
    public AuthenticationController(RSASHA1SignatureUtil rsasha1SignatureUtil,
                                    RestTemplate restTemplate,
                                    ObjectMapper objectMapper) {
        this.rsasha1SignatureUtil = rsasha1SignatureUtil;
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    @RequestMapping
    public ResponseEntity<?> handle(HttpEntity<String> httpEntity, HttpServletRequest request) throws IOException {
        HttpHeaders headers = httpEntity.getHeaders();

        verifyRequest(httpEntity, headers);

        ResponseEntity<String> targetApplicationResponse = callTargetApplication(httpEntity, request, headers);


        Message signedMessage = signTargetResponse(targetApplicationResponse.getBody());

        HttpHeaders responseHeaders = createResponseHeaders(targetApplicationResponse, signedMessage);


        return new ResponseEntity<Object>(signedMessage.getMessage(),
                responseHeaders,
                HttpStatus.valueOf(targetApplicationResponse.getStatusCodeValue()));

    }

    private Message signTargetResponse(String message) {
        return rsasha1SignatureUtil.sign(message);
    }

    private HttpHeaders createResponseHeaders(ResponseEntity<String> targetApplicationResponse, Message signedMessage) {
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.putAll(targetApplicationResponse.getHeaders());
        responseHeaders.put(X_CONTENT_DIGEST, newArrayList(signedMessage.getDigest()));
        responseHeaders.put(X_SIGNATURE, newArrayList(signedMessage.getSignature()));
        return responseHeaders;
    }

    private void verifyRequest(HttpEntity<String> httpEntity, HttpHeaders headers) throws IOException {

        assertBody(httpEntity);
        assertHeaderNotEmpty(httpEntity, X_CONTENT_DIGEST);
        assertHeaderNotEmpty(httpEntity, X_SIGNATURE);


        rsasha1SignatureUtil.verify(new Message(httpEntity.getBody(), headers.get(X_CONTENT_DIGEST).get(0), headers.get(X_SIGNATURE).get(0)));
    }

    private ResponseEntity<String> callTargetApplication(HttpEntity<String> httpEntity, HttpServletRequest request, HttpHeaders headers) {
        ResponseEntity<String> targetApplicationResponseEntity;

        try {
            RequestEntity<String> requestEntity = new RequestEntity<>(httpEntity.getBody(),
                    headers,
                    HttpMethod.resolve(request.getMethod()),
                    URI.create(format("http://hello/%s", request.getRequestURI())));
            return restTemplate.exchange(requestEntity, String.class);
        } catch (Exception e) {
            throw new TargetApplicationException("Some shit happened while calling the target application", e);
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

    @ExceptionHandler(value = TargetApplicationException.class)
    public ResponseEntity<?> handleTargetApplicationException(TargetApplicationException e) {
        ErrorResponse error = ErrorResponse.dummyErrorResponse();
        return handleErrorResponse(error, e);
    }

    @ExceptionHandler(value = SignatureVerifyingException.class)
    public ResponseEntity<?> handleRequestVerificationException(TargetApplicationException e) {
        ErrorResponse error = ErrorResponse.dummyErrorResponse();
        return handleErrorResponse(error, e);
    }

    @ExceptionHandler(value = ResponseSigningException.class)
    public ResponseEntity<?> handleResponseSigningException(TargetApplicationException e) {
        ErrorResponse error = ErrorResponse.dummyErrorResponse();
        return handleErrorResponse(error, e);
    }

    @ExceptionHandler(value = Exception.class)
    public ResponseEntity<?> handleUnknownException(Exception e) {
        ErrorResponse error = ErrorResponse.dummyErrorResponse();
        return handleErrorResponse(error, e);
    }

    private ResponseEntity<?> handleErrorResponse(ErrorResponse error, Exception e) {
        log.warn("Error for verifying or signing ", e);
        try {
            String errorResponse = objectMapper.writer().writeValueAsString(error);
            Message message = signTargetResponse(errorResponse);
            HttpHeaders responseHeaders = new HttpHeaders();
            responseHeaders.put(X_CONTENT_DIGEST, newArrayList(message.getDigest()));
            responseHeaders.put(X_SIGNATURE, newArrayList(message.getSignature()));
            return new ResponseEntity<Object>(message.getMessage(),
                    responseHeaders,
                    HttpStatus.OK);
        } catch (Exception x) {
            throw new RuntimeException("Error during creation of error response", x);
        }
    }
}
