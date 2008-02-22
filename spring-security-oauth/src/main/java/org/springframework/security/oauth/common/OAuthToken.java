package org.springframework.security.oauth.common;

/**
 * An OAuth token.
 *
 * @author Ryan Heaton
 */
public class OAuthToken {

  private final String value;
  private final String secret;

  public OAuthToken(String value, String secret) {
    this.value = value;
    this.secret = secret;
  }

  /**
   * The id of the token.
   *
   * @return The id of the token.
   */
  public String getValue() {
    return value;
  }

  /**
   * The token secret.
   *
   * @return The token secret.
   */
  public String getSecret() {
    return secret;
  }

}
