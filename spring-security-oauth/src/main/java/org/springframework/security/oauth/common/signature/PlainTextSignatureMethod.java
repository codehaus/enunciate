package org.springframework.security.oauth.common.signature;

import static org.springframework.security.oauth.common.OAuthCodec.*;

/**
 * Plain text signature method.
 *
 * @author Ryan Heaton
 */
public class PlainTextSignatureMethod implements OAuthSignatureMethod {

  /**
   * The name of this plain text signature method ("PLAINTEXT").
   */
  public static final String SIGNATURE_NAME = "PLAINTEXT";

  private final String secret;

  /**
   * Construct a plain text signature method with the given plain-text secret.
   *
   * @param secret The secret.
   */
  public PlainTextSignatureMethod(String secret) {
    this.secret = secret;
  }

  /**
   * The name of this plain text signature method ("PLAINTEXT").
   *
   * @return The name of this plain text signature method.
   */
  public String getName() {
    return SIGNATURE_NAME;
  }

  /**
   * The signature is the same as the secret.
   *
   * @param signatureBaseString The signature base string (unimportant, ignored).
   * @return The secret.
   */
  public String sign(String signatureBaseString) {
    return this.secret;
  }

  /**
   * Validates that the signature is the same as the secret.
   *
   * @param signatureBaseString The signature base string (unimportant, ignored).
   * @param signature The signature.
   * @throws InvalidSignatureException If the signature is not the same as the secret.
   */
  public void verify(String signatureBaseString, String signature) throws InvalidSignatureException {
    if (!signature.equals(this.secret)) {
      throw new InvalidSignatureException("Invalid signature for signature method " + getName());
    }
  }
}
