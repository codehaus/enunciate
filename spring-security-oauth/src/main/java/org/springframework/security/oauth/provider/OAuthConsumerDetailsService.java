package org.springframework.security.oauth.provider;

import org.acegisecurity.AuthenticationException;
import org.springframework.security.oauth.common.OAuthToken;
import org.springframework.security.oauth.common.signature.SignatureSecret;

/**
 * A service that provides the details about an oauth consumer.
 *
 * @author Ryan Heaton
 */
public interface OAuthConsumerDetailsService {

  /**
   * Whether the specified consumer key is valid.
   *
   * @param consumerKey The consumer key.
   * @return Whether the specified key is valid.
   */
  boolean isValid(String consumerKey);

  /**
   * Validate a nonce for a specific consumer timestamp. This is an opportunity to prevent replay attacks.  Every nonce
   * should be unique for each consumer timestamp. In other words, this method should throw a BadCredentialsException
   * if the specified nonce was used by the consumer more than once with the specified timestamp.
   *
   * @param consumerKey The consumer key.
   * @param timestamp The timestamp.
   * @param nonce The nonce.
   * @throws AuthenticationException If the nonce failed to validate.
   */
  void validateNonce(String consumerKey, long timestamp, String nonce) throws AuthenticationException;

  /**
   * Get the signature secret for the specified consumer.
   *
   * @param consumerKey The consumer key.
   * @param token The token, or null if none. This may be null if the consumer didn't supply a token (e.g. the consumer
   *              is requesting a new request token.
   * @return The signature secret for the specified consumer.
   * @throws AuthenticationException If the consumer or the secret isn't found.
   */
  SignatureSecret getSignatureSecret(String consumerKey, String token) throws AuthenticationException;

  /**
   * Create an unauthenticated OAuth token.
   *
   * @param consumerKey The consumer key for which to create the token.
   * @return The token.
   */
  OAuthToken createUnauthenticatedToken(String consumerKey);

  /**
   * Authorize the specified request token. After the request token is authorized, a conumer can use it to
   * obtain an access token that can be used to access the protected resources.
   *
   * @param requestToken The request token.
   */
  void authorizeRequestToken(String requestToken) throws AuthenticationException;

  /**
   * Create an OAuth access token.
   *
   * @param consumerKey The consumer key for which to create the token.
   * @return The token.
   */
  OAuthToken createAccessToken(String consumerKey);
}
