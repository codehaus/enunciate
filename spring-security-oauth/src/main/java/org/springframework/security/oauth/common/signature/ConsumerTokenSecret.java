package org.springframework.security.oauth.common.signature;

/**
 * A signature secret that consists of a consumer secret and a tokent secret.
 *
 * @author Ryan Heaton
 */
public class ConsumerTokenSecret {

  private final String consumerSecret;
  private final String tokenSecret;

  public ConsumerTokenSecret(String consumerSecret, String tokenSecret) {
    this.consumerSecret = consumerSecret;
    this.tokenSecret = tokenSecret;
  }

  /**
   * The consumer secret.
   *
   * @return The consumer secret.
   */
  public String getConsumerSecret() {
    return consumerSecret;
  }

  /**
   * The token secret.
   *
   * @return The token secret.
   */
  public String getTokenSecret() {
    return tokenSecret;
  }
}
