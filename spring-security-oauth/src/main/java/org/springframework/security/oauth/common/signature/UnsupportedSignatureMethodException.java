package org.springframework.security.oauth.common.signature;

import org.acegisecurity.AuthenticationException;

/**
 * @author Ryan Heaton
 */
public class UnsupportedSignatureMethodException extends AuthenticationException {

  public UnsupportedSignatureMethodException(String msg) {
    super(msg);
  }
}
