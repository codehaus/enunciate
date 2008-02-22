package org.springframework.security.oauth.provider.nonce;

import org.acegisecurity.AuthenticationException;

/**
 * @author Ryan Heaton
 */
public class NonceAlreadyUsedException extends AuthenticationException {
  public NonceAlreadyUsedException(String msg) {
    super(msg);
  }
}
