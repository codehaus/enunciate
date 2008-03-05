package org.springframework.security.oauth.consumer.token;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;

/**
 * Token services for an OAuth consumer.
 * 
 * @author Ryan Heaton
 */
public interface OAuthConsumerTokenServices {

  /**
   * Get the token for the specified protected resource that is applicable
   * to the given authentication credentials.
   *
   * @param resourceId The id of the protected resource.
   * @param authentication The authentication
   * @return The token, or null if none was found.
   */
  OAuthConsumerToken getToken(String resourceId, Authentication authentication) throws AuthenticationException;

  /**
   * Store a token for a specified resource on behalf
   * of the specified authentication.
   *
   * @param resourceId The id of the protected resource.
   * @param authentication The authentication to which the access token is applicable.
   * @param token The token to store.
   */
  void storeToken(String resourceId, Authentication authentication, OAuthConsumerToken token);

}
