package org.springframework.security.oauth.provider.token;

import org.springframework.security.oauth.common.OAuthToken;
import org.acegisecurity.AuthenticationException;

/**
 * @author Ryan Heaton
 */
public interface OAuthTokenServices {

  /**
   * Read a token by its value for the given consumer key.
   *
   * @param token The token value.
   * @param consumerKey The consumer key.
   * @return The token.
   * @throws AuthenticationException If the token is invalid or expired for the specified consumer.
   */
  OAuthToken getToken(String token, String consumerKey) throws AuthenticationException;

  /**
   * Create an unauthorized OAuth request token.
   *
   * @param consumerKey The consumer key for which to create the token.
   * @return The token.
   * @throws AuthenticationException If the consumer isn't valid or otherwise isn't allowed to create a new request token.
   */
  OAuthToken createUnauthorizedRequestToken(String consumerKey) throws AuthenticationException;

  /**
   * Authorize the specified request token for the given consumer. After the request token is authorized, the consumer will be able to
   * use it to obtain an access token.
   *
   * @param requestToken The request token.
   * @param consumerKey The consumer key.
   * @throws AuthenticationException If the consumer isn't valid for the given token or if the token is expired or otherwise unauthorizable.
   */
  void authorizeRequestToken(String requestToken, String consumerKey) throws AuthenticationException;

  /**
   * Whether the specified request token is authorized for the specified consumer.
   *
   * @param requestToken The request token.
   * @param consumerKey The consumer key.
   * @return The request token.
   */
  boolean isAuthorizedRequestToken(String requestToken, String consumerKey);

  /**
   * Create an OAuth access token. This token will be used to provide access to a protected resource.
   *
   * @param consumerKey The consumer key for which to create the token.
   * @return The access token.
   * @throws AuthenticationException If the consumer isn't valid or otherwise isn't allowed to create an access token.
   */
  OAuthToken createAccessToken(String consumerKey) throws AuthenticationException;

  /**
   * Whether the specified access token is valid for the given consumer.
   *
   * @param accessToken The access token.
   * @param consumerKey The consumer key.
   * @return Whether the specified access token is valid for the given consumer.
   */
  boolean isValidAccessToken(String accessToken, String consumerKey);
}
