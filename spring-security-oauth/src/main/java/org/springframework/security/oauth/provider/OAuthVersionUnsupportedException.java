package org.springframework.security.oauth.provider;

import org.acegisecurity.AuthenticationException;

/**
 * @author Ryan Heaton
 */
public class OAuthVersionUnsupportedException extends AuthenticationException {

  public OAuthVersionUnsupportedException(String msg) {
    super(msg);
  }
}
