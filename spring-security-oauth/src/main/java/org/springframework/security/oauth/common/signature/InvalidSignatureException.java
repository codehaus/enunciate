package org.springframework.security.oauth.common.signature;

import org.acegisecurity.AuthenticationException;

/**
 * Thrown when a signature is invalid.
 *
 * @author Ryan Heaton
 */
public class InvalidSignatureException extends AuthenticationException {

  public InvalidSignatureException(String msg) {
    super(msg);
  }

  public InvalidSignatureException(String msg, Throwable t) {
    super(msg, t);
  }
}
