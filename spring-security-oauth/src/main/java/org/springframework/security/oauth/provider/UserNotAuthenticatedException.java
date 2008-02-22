package org.springframework.security.oauth.provider;

import org.acegisecurity.AuthenticationException;

/**
 * @author Ryan Heaton
 */
public class UserNotAuthenticatedException extends AuthenticationException {

  public UserNotAuthenticatedException(String msg) {
    super(msg);
  }
}
