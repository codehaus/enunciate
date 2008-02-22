package org.springframework.security.oauth.common;

/**
 * Empty OAuth token.
 * 
 * @author Ryan Heaton
 */
public class EmptyOAuthToken extends OAuthToken {

  public EmptyOAuthToken() {
    super(null, null);
  }
  
}
