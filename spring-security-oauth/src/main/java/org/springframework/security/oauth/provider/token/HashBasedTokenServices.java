package org.springframework.security.oauth.provider.token;

import org.springframework.security.oauth.common.OAuthToken;
import org.springframework.beans.factory.InitializingBean;
import org.acegisecurity.AuthenticationException;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.binary.Base64;

import java.util.Random;

/**
 * Base implementation for token services that use a hash to generate/validate tokens. Only the persistence
 * mechanism is left unimplemented.<br/><br/>
 *
 * The token values will have a timestamp prepended so as to check for expiration.<br/><br/>
 *
 * This base implementation does a lot of hashing to looking tokens and token secrets. If performance is an
 * issue, consider overriding any (or all) of the following methods:
 *
 * <ul>
 *   <li>{@link #createTokenValue(String, long)}</li>
 *   <li>{@link #loadTokenSecret(String, String)}</li>
 *   <li>{@link #isAuthorizedRequestToken(String, String)}</li>
 * </ul>
 *
 * @author Ryan Heaton
 */
public abstract class HashBasedTokenServices implements OAuthTokenServices, InitializingBean {

  private String hashKey;
  private int requestTokenValiditySeconds = 60 * 10; //default 10 minutes.
  private int accessTokenValiditySeconds = 60 * 60 * 12; //default 12 hours.

  public void afterPropertiesSet() throws Exception {
    if (hashKey == null) {
      byte[] bytes = new byte[100];
      bytes = Base64.encodeBase64(bytes);
      new Random().nextBytes(bytes);
      hashKey = new String(bytes, "UTF-8");
    }
  }

  // Inherited.
  public OAuthToken getToken(String token, String consumerKey) throws AuthenticationException {
    validateToken(token, consumerKey);
    return new OAuthToken(token, loadTokenSecret(consumerKey, token));
  }

  /**
   * Validate the specified token for the specified consumer.
   *
   * @param token       The token to validate.
   * @param consumerKey The consumer key.
   */
  protected void validateToken(String token, String consumerKey) {
    if (token == null) {
      throw new IllegalArgumentException("Token cannot be null.");
    }
    if (consumerKey == null) {
      throw new IllegalArgumentException("Consumer key cannot be null.");
    }

    int colonIndex = token.indexOf(':');
    if (colonIndex < 0) {
      throw new InvalidOAuthTokenException("Invalid OAuth token: " + token);
    }

    String timestampValue = token.substring(0, colonIndex);
    long timestamp;
    try {
      timestamp = Long.parseLong(timestampValue);
    }
    catch (NumberFormatException e) {
      throw new InvalidOAuthTokenException("Invalid OAuth token: " + token);
    }

    if (System.currentTimeMillis() - timestamp > getRequestTokenValiditySeconds()) {
      throw new ExpiredOAuthTokenException("Expired token: " + token);
    }

    String tokenValue = createTokenValue(consumerKey, timestamp);
    if (!tokenValue.equals(token)) {
      throw new InvalidOAuthTokenException("Invalid OAuth token: " + token);
    }
  }

  /**
   * Create a token value for the given consumer and timestamp.
   *
   * @param consumerKey The consumer key.
   * @param timestamp   The timestamp.
   * @return The token value.
   */
  protected String createTokenValue(String consumerKey, long timestamp) {
    return new StringBuilder().append(timestamp).append(':').append(getHash(consumerKey, String.valueOf(timestamp))).toString();
  }

  /**
   * Get the token secret for the given consumer and token value.
   *
   * @param consumerKey The consumer key.
   * @param tokenValue  The token value.
   * @return The token secret.
   */
  protected String loadTokenSecret(String consumerKey, String tokenValue) {
    return getHash(consumerKey, tokenValue);
  }

  /**
   * Get the hash for the specified consumer key and seed.
   *
   * @param consumerKey The consumer key.
   * @param seed        The seed for the hash.
   * @return The hash.
   */
  protected String getHash(String consumerKey, String seed) {
    return DigestUtils.md5Hex(new StringBuilder(consumerKey).append(":").append(seed).append(":").append(getHashKey()).toString());
  }

  // Inherited.
  public OAuthToken createUnauthorizedRequestToken(String consumerKey) throws AuthenticationException {
    long timestamp = System.currentTimeMillis();
    String tokenValue = createTokenValue(consumerKey, timestamp);
    String tokenSecret = loadTokenSecret(consumerKey, tokenValue);
    OAuthToken authToken = new OAuthToken(tokenValue, tokenSecret);
    storeUnauthorizedRequestToken(authToken);
    return authToken;
  }

  /**
   * Store an unauthorized request token.  Default implementation does nothing, since an unauthorized
   * token doesn't need to be stored (it can be calculated).
   *
   * @param authToken The unauthorized request token.
   */
  protected void storeUnauthorizedRequestToken(OAuthToken authToken) {
    //no-op
  }

  // Inherited.
  public void authorizeRequestToken(String requestToken, String consumerKey) throws AuthenticationException {
    OAuthToken authToken = getToken(requestToken, consumerKey);
    storeAuthorizedRequestToken(authToken);
  }

  /**
   * Store an authorized request token.
   *
   * @param authToken The auth token.
   */
  protected abstract void storeAuthorizedRequestToken(OAuthToken authToken);

  // Inherited.
  public boolean isAuthorizedRequestToken(String requestToken, String consumerKey) {
    OAuthToken authToken = getToken(requestToken, consumerKey);
    return isAuthorizedRequestToken(authToken);
  }

  /**
   * Whether the specified auth token is authorized. I.e. whether the {@link #storeAuthorizedRequestToken(org.springframework.security.oauth.common.OAuthToken)}
   * method has been called for this token.
   *
   * @param authToken The auth token.
   * @return Whether the token has been authorized.
   */
  protected abstract boolean isAuthorizedRequestToken(OAuthToken authToken);

  // Inherited.
  public OAuthToken createAccessToken(String consumerKey) throws AuthenticationException {
    OAuthToken newToken = createUnauthorizedRequestToken(consumerKey);
    storeAccessToken(newToken);
    return newToken;
  }

  // Inherited.
  public boolean isValidAccessToken(String accessToken, String consumerKey) {
    OAuthToken authToken = getToken(accessToken, consumerKey);
    return isValidAccessToken(authToken);
  }

  /**
   * Store the specified access token.
   *
   * @param accessToken The new access token
   */
  protected abstract void storeAccessToken(OAuthToken accessToken);

  /**
   * Whether the specified auth token is valid. I.e. whether the {@link #storeAccessToken(org.springframework.security.oauth.common.OAuthToken)}
   * method has been called for this token.
   *
   * @param authToken The auth token.
   * @return Whether the token has been valid.
   */
  protected abstract boolean isValidAccessToken(OAuthToken authToken);

  /**
   * The hash key for these services.
   *
   * @return The hash key for these services.
   */
  public String getHashKey() {
    return hashKey;
  }

  /**
   * The hash key for these services.
   *
   * @param hashKey The hash key for these services.
   */
  public void setHashKey(String hashKey) {
    this.hashKey = hashKey;
  }

  /**
   * The validity (in seconds) of the unauthenticated request token.
   *
   * @return The validity (in seconds) of the unauthenticated request token.
   */
  public int getRequestTokenValiditySeconds() {
    return requestTokenValiditySeconds;
  }

  /**
   * The validity (in seconds) of the unauthenticated request token.
   *
   * @param requestTokenValiditySeconds The validity (in seconds) of the unauthenticated request token.
   */
  public void setRequestTokenValiditySeconds(int requestTokenValiditySeconds) {
    this.requestTokenValiditySeconds = requestTokenValiditySeconds;
  }

  /**
   * The validity (in seconds) of the access token.
   *
   * @return The validity (in seconds) of the access token.
   */
  public int getAccessTokenValiditySeconds() {
    return accessTokenValiditySeconds;
  }

  /**
   * The validity (in seconds) of the access token.
   *
   * @param accessTokenValiditySeconds The validity (in seconds) of the access token.
   */
  public void setAccessTokenValiditySeconds(int accessTokenValiditySeconds) {
    this.accessTokenValiditySeconds = accessTokenValiditySeconds;
  }
}
