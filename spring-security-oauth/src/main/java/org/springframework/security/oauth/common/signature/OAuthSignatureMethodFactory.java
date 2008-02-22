package org.springframework.security.oauth.common.signature;

import org.springframework.security.oauth.common.OAuthToken;

/**
 * Factory for signature methods.
 *
 * @author Ryan Heaton
 */
public interface OAuthSignatureMethodFactory {

  /**
   * Get the signature method of the given name.
   *
   * @param methodName      The method name.
   * @param signatureSecret The signature secret.
   * @param token
   * @return the signature method.
   * @throws UnsupportedSignatureMethodException If the specified signature method name isn't recognized or supported.
   */
  OAuthSignatureMethod getSignatureMethod(String methodName, SignatureSecret signatureSecret, OAuthToken token) throws UnsupportedSignatureMethodException;
}
