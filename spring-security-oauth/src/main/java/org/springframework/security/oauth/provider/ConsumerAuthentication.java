package org.springframework.security.oauth.provider;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;

/**
 * Authentication for an OAuth consumer.
 * 
 * @author Ryan Heaton
 */
public class ConsumerAuthentication extends AbstractAuthenticationToken {

  private final ConsumerDetails consumerDetails;
  private final ConsumerCredentials consumerCredentials;
  private GrantedAuthority[] grantedAuthorities;
  private boolean signatureValidated = false;

  public ConsumerAuthentication(ConsumerDetails consumerDetails, ConsumerCredentials consumerCredentials) {
    this.consumerDetails = consumerDetails;
    this.consumerCredentials = consumerCredentials;
  }

  /**
   * The authorities of a consumer consist of the authorities {@link org.springframework.security.oauth.provider.ConsumerDetails#getAuthorities() inherent
   * to consumer} and any authorities that have been {@link #grantAuthorities(org.acegisecurity.GrantedAuthority[]) granted} to the consumer via an
   * OAuth access token.
   *
   * @return The authorities of the consumer.
   */
  @Override
  public GrantedAuthority[] getAuthorities() {
    return this.grantedAuthorities == null ? getConsumerDetails().getAuthorities() : join(getConsumerDetails().getAuthorities(), this.grantedAuthorities);
  }

  /**
   * Grant additional authorities to the authenticated consumer, e.g. from an OAuth access token.
   *
   * @param authorities The authorities to grant.
   * @throws IllegalStateException if the signature hasn't been validated.
   */
  public void grantAuthorities(GrantedAuthority[] authorities) {
    if (!isSignatureValidated()) {
      throw new IllegalStateException("Cannot grant additional authorities: consumer signature hasn't been validated.");
    }

    this.grantedAuthorities = authorities;
  }

  /**
   * The credentials.
   *
   * @return The credentials.
   * @see #getConsumerCredentials()
   */
  public Object getCredentials() {
    return getConsumerCredentials();
  }

  /**
   * The credentials of this authentication.
   *
   * @return The credentials of this authentication.
   */
  public ConsumerCredentials getConsumerCredentials() {
    return consumerCredentials;
  }

  /**
   * The principal ({@link #getConsumerDetails() consumer details}).
   *
   * @return The principal.
   * @see #getConsumerDetails()
   */
  public Object getPrincipal() {
    return getConsumerDetails();
  }

  /**
   * The consumer details.
   *
   * @return The consumer details.
   */
  public ConsumerDetails getConsumerDetails() {
    return consumerDetails;
  }

  /**
   * The name of this principal is the consumer key.
   *
   * @return The name of this principal is the consumer key.
   */
  public String getName() {
    return getConsumerDetails() != null ? getConsumerDetails().getConsumerKey() : null;
  }

  /**
   * Whether the signature has been validated.
   *
   * @return Whether the signature has been validated.
   */
  public boolean isSignatureValidated() {
    return signatureValidated;
  }

  /**
   * Whether the signature has been validated.
   *
   * @param signatureValidated Whether the signature has been validated.
   */
  public void setSignatureValidated(boolean signatureValidated) {
    this.signatureValidated = signatureValidated;
  }

  /**
   * Whether the signature has been validated.
   *
   * @return Whether the signature has been validated.
   */
  @Override
  public boolean isAuthenticated() {
    return isSignatureValidated();
  }

  /**
   * Whether the signature has been validated.
   *
   * @param authenticated Whether the signature has been validated.
   */
  @Override
  public void setAuthenticated(boolean authenticated) {
    setSignatureValidated(authenticated);
  }

  private static GrantedAuthority[] join(GrantedAuthority[] consumerAuthorities, GrantedAuthority[] grantedAuthorities) {
    GrantedAuthority[] result = new GrantedAuthority[consumerAuthorities.length + grantedAuthorities.length];
    System.arraycopy(consumerAuthorities, 0, result, 0, consumerAuthorities.length);
    System.arraycopy(grantedAuthorities, 0, result, consumerAuthorities.length - 1, grantedAuthorities.length);
    return result;
  }
}
