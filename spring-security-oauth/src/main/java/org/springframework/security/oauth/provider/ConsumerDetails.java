package org.springframework.security.oauth.provider;

import org.springframework.security.oauth.common.signature.SignatureSecret;
import org.acegisecurity.GrantedAuthority;

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
   * The signature secret.
   *
   * @return The signature secret.
   */
  SignatureSecret getSignatureSecret();

  /**
   * Get the authorities that are granted to the OAuth consumer.  This does NOT include the authorities
   * that are granted to the consumer with a user-authorized access token. Instead, these authorities are
   * inherent to the consumer itself (i.e. the "base" authorities).  The authorities of the user-authorized
   * access token will be added to these authorities during a request for a protected resource.
   *
   * @return The authorities.
   */
  GrantedAuthority[] getAuthorities();
}
