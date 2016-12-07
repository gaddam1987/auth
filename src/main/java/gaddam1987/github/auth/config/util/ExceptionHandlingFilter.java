package gaddam1987.github.auth.config.util;

import gaddam1987.github.auth.config.Message;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class ExceptionHandlingFilter implements Filter {
    private final String UNCAUGHT_ERROR_RESPONSE = "{" +
            "\"errorCode\": \"8236\"," +
            "\"errorMessage\": \"Some thing really bad happened\"" +
            "}";

    private final String X_CONTENT_DIGEST = "X-Content-Digest";
    private final String X_SIGNATURE = "X-Signature";


    private final RSASHA1SignatureUtil signatureUtil;


    public ExceptionHandlingFilter(RSASHA1SignatureUtil signatureUtil) {
        this.signatureUtil = signatureUtil;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        try {
            filterChain.doFilter(servletRequest, servletResponse);
        } catch (Throwable e) {
            log.error("Something Fishy", e);
            Message signErrorMessage = signatureUtil.sign(UNCAUGHT_ERROR_RESPONSE);
            HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
            httpServletResponse.setHeader(X_CONTENT_DIGEST, signErrorMessage.getDigest());
            httpServletResponse.setHeader(X_SIGNATURE, signErrorMessage.getSignature());
            ServletOutputStream outputStream = httpServletResponse.getOutputStream();
            outputStream.print(UNCAUGHT_ERROR_RESPONSE);
            outputStream.flush();
        }
    }

    @Override
    public void destroy() {
    }
}
