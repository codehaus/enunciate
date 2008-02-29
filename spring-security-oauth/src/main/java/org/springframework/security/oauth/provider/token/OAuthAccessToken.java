package org.springframework.security.oauth.provider.token;

import org.acegisecurity.Authentication;

/**
 * @author Ryan Heaton
 */
public interface OAuthAccessToken extends OAuthToken {

  /**
   * Get the authentication of the user who authorized the access token.
   *
   * @return the authentication of the user who authorized the access token.
   */
  Authentication getUserAuthentication();

}
