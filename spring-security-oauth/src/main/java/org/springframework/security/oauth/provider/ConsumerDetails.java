package org.springframework.security.oauth.provider;

import org.acegisecurity.GrantedAuthority;
import org.springframework.security.oauth.common.signature.SignatureSecret;

import java.io.Serializable;

/**
 * Provides core OAuth consumer information.
 *
 * @author Ryan Heaton
 */
public interface ConsumerDetails extends Serializable {

  /**
   * The consumer key.
   *
   * @return The consumer key.
   */
  String getConsumerKey();

  /**
   * Returns the authorities granted to the user. Cannot return <code>null</code>.
   *
   * @return the authorities (never <code>null</code>)
   */
  GrantedAuthority[] getAuthorities();

  /**
   * The signature secret.
   *
   * @return The signature secret.
   */
  SignatureSecret getSignatureSecret();
}
