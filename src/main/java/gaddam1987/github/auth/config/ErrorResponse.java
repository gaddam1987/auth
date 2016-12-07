package gaddam1987.github.auth.config;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
class ErrorResponse {
    private final String errorCode;
    private final String errorMessage;

    static ErrorResponse dummyErrorResponse() {
        return new ErrorResponse("1234", "custom error message");
    }
}
