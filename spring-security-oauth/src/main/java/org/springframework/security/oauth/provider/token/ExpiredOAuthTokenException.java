package org.springframework.security.oauth.provider.token;

import org.acegisecurity.AuthenticationException;

/**
 * @author Ryan Heaton
 */
public class ExpiredOAuthTokenException extends AuthenticationException {

  public ExpiredOAuthTokenException(String msg) {
    super(msg);
  }
}