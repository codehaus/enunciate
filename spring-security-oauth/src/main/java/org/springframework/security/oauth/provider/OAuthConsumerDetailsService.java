package org.springframework.security.oauth.provider;

import org.acegisecurity.BadCredentialsException;

/**
 * A service that provides the details about an oauth consumer.
 *
 * @author Ryan Heaton
 */
public interface OAuthConsumerDetailsService {

  /**
   * Validate a nonce for a specific consumer timestamp. This is an opportunity to prevent replay attacks.  Every nonce
   * should be unique for each consumer timestamp. In other words, this method should throw a BadCredentialsException
   * if the specified nonce was used by the consumer more than once with the specified timestamp.
   *
   * @param consumerKey The consumer key.
   * @param timestamp The timestamp.
   * @param nonce The nonce.
   * @throws BadCredentialsException If the nonce failed to validate.
   */
  void validateNonce(String consumerKey, long timestamp, String nonce) throws BadCredentialsException;
}
