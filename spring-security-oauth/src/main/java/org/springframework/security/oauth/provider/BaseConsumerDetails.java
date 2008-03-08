package org.springframework.security.oauth.provider;

import org.springframework.security.oauth.common.signature.SignatureSecret;
import org.acegisecurity.GrantedAuthority;

/**
 * Base implementation for consumer details.
 *
 * @author Ryan Heaton
 */
public class BaseConsumerDetails implements ConsumerDetails {

  private String consumerKey;
  private SignatureSecret signatureSecret;
  private GrantedAuthority[] authorities = new GrantedAuthority[0];

  /**
   * The consumer key.
   *
   * @return The consumer key.
   */
  public String getConsumerKey() {
    return consumerKey;
  }

  /**
   * The consumer key.
   *
   * @param consumerKey The consumer key.
   */
  public void setConsumerKey(String consumerKey) {
    this.consumerKey = consumerKey;
  }

  /**
   * The signature secret.
   *
   * @return The signature secret.
   */
  public SignatureSecret getSignatureSecret() {
    return signatureSecret;
  }

  /**
   * The signature secret.
   *
   * @param signatureSecret The signature secret.
   */
  public void setSignatureSecret(SignatureSecret signatureSecret) {
    this.signatureSecret = signatureSecret;
  }

  /**
   * The base authorities for this consumer.
   *
   * @return The base authorities for this consumer.
   */
  public GrantedAuthority[] getAuthorities() {
    return authorities;
  }

  /**
   * The base authorities for this consumer.
   *
   * @param authorities The base authorities for this consumer.
   */
  public void setAuthorities(GrantedAuthority[] authorities) {
    this.authorities = authorities;
  }
}
