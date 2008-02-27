package org.springframework.security.oauth.provider.token;

import org.acegisecurity.GrantedAuthority;

import java.util.Arrays;

/**
 * Basic implementation for an OAuth token.
 *
 * @author Ryan Heaton
 */
public class OAuthTokenImpl implements OAuthAccessToken {

  private String value;
  private String secret;
  private String consumerKey;
  private boolean accessToken;
  private GrantedAuthority[] grantedAuthorities;
  private long timestamp;

  /**
   * The value of the token.
   *
   * @return The value of the token.
   */
  public String getValue() {
    return value;
  }

  /**
   * The value of the token.
   *
   * @param value The value of the token.
   */
  public void setValue(String value) {
    this.value = value;
  }

  /**
   * The token secret.
   *
   * @return The token secret.
   */
  public String getSecret() {
    return secret;
  }

  /**
   * The token secret.
   *
   * @param secret The token secret.
   */
  public void setSecret(String secret) {
    this.secret = secret;
  }

  /**
   * The consumer key associated with this oauth token.
   *
   * @return The consumer key associated with this oauth token.
   */
  public String getConsumerKey() {
    return consumerKey;
  }

  /**
   * The consumer key associated with this oauth token.
   *
   * @param consumerKey The consumer key associated with this oauth token.
   */
  public void setConsumerKey(String consumerKey) {
    this.consumerKey = consumerKey;
  }

  /**
   * Whether this is an OAuth access token.
   *
   * @return Whether this is an OAuth access token.
   */
  public boolean isAccessToken() {
    return accessToken;
  }

  /**
   * Whether this is an OAuth access token.
   *
   * @param accessToken Whether this is an OAuth access token.
   */
  public void setAccessToken(boolean accessToken) {
    this.accessToken = accessToken;
  }

  /**
   * The authorities granted along with this (presumable) access token.
   *
   * @return The authorities granted along with this (presumable) access token.
   */
  public GrantedAuthority[] getGrantedAuthorities() {
    return grantedAuthorities;
  }

  /**
   * The authorities granted along with this (presumable) access token.
   *
   * @param grantedAuthorities The authorities granted along with this (presumable) access token.
   */
  public void setGrantedAuthorities(GrantedAuthority[] grantedAuthorities) {
    this.grantedAuthorities = grantedAuthorities;
  }

  /**
   * Timestamp associated with this token.
   *
   * @return Timestamp associated with this token.
   */
  public long getTimestamp() {
    return timestamp;
  }

  /**
   * Timestamp associated with this token.
   *
   * @param timestamp Timestamp associated with this token.
   */
  public void setTimestamp(long timestamp) {
    this.timestamp = timestamp;
  }

  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    OAuthTokenImpl that = (OAuthTokenImpl) o;

    if (accessToken != that.accessToken) {
      return false;
    }
    if (timestamp != that.timestamp) {
      return false;
    }
    if (consumerKey != null ? !consumerKey.equals(that.consumerKey) : that.consumerKey != null) {
      return false;
    }
    if (!Arrays.equals(grantedAuthorities, that.grantedAuthorities)) {
      return false;
    }
    if (secret != null ? !secret.equals(that.secret) : that.secret != null) {
      return false;
    }
    if (value != null ? !value.equals(that.value) : that.value != null) {
      return false;
    }

    return true;
  }

  public int hashCode() {
    int result;
    result = (value != null ? value.hashCode() : 0);
    result = 31 * result + (secret != null ? secret.hashCode() : 0);
    result = 31 * result + (consumerKey != null ? consumerKey.hashCode() : 0);
    result = 31 * result + (accessToken ? 1 : 0);
    result = 31 * result + (grantedAuthorities != null ? Arrays.hashCode(grantedAuthorities) : 0);
    result = 31 * result + (int) (timestamp ^ (timestamp >>> 32));
    return result;
  }
}
