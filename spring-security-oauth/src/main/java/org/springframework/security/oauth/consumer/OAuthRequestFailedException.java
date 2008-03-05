package org.springframework.security.oauth.consumer;

import org.acegisecurity.AuthenticationException;

/**
 * Thrown when an OAuth request fails.
 *
 * @author Ryan Heaton
 */
public class OAuthRequestFailedException extends AuthenticationException {

  public OAuthRequestFailedException(String msg) {
    super(msg);
  }

  public OAuthRequestFailedException(String msg, Throwable t) {
    super(msg, t);
  }
}
