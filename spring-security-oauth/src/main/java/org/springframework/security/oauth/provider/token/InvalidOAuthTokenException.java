package org.springframework.security.oauth.provider.token;

import org.acegisecurity.AuthenticationException;

/**
 * @author Ryan Heaton
 */
public class InvalidOAuthTokenException extends AuthenticationException {

  public InvalidOAuthTokenException(String msg) {
    super(msg);
  }
}
