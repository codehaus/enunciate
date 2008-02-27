package org.springframework.security.oauth.provider;

import org.acegisecurity.BadCredentialsException;

/**
 * @author Ryan Heaton
 */
public class InvalidOAuthParametersException extends BadCredentialsException {

  public InvalidOAuthParametersException(String msg) {
    super(msg);
  }
}
