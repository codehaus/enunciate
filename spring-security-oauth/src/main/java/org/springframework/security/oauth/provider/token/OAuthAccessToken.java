package org.springframework.security.oauth.provider.token;

import org.acegisecurity.GrantedAuthority;

/**
 * @author Ryan Heaton
 */
public interface OAuthAccessToken extends OAuthToken {
  /**
   * The authorities granted along with this (presumable) access token.
   *
   * @return The authorities granted along with this (presumable) access token.
   */
  GrantedAuthority[] getGrantedAuthorities();
}
