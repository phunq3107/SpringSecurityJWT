package com.phunq.springsecurityjwt.api;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

import com.phunq.springsecurityjwt.exception.RoleNameNotExists;
import com.phunq.springsecurityjwt.exception.UsernameNotExists;
import java.util.HashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
@RestControllerAdvice
public class HandleException extends ResponseEntityExceptionHandler {

  @ExceptionHandler({UsernameNotExists.class, RoleNameNotExists.class})
  @ResponseStatus(BAD_REQUEST)
  public Map<String, String> handleNotExistException(Exception ex) {
    return new HashMap<>() {{
      put("code", BAD_REQUEST.toString());
      put("message", ex.getMessage());
    }};
  }

}
