package org.springframework.security.oauth.provider;

import org.acegisecurity.BadCredentialsException;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.OAuthToken;

import java.util.Map;

/**
 * Processing filter for handling a request for an OAuth access token.
 *
 * @author Ryan Heaton
 */
public class OAuthAccessTokenProcessingFilter extends OAuthTokenProcessingFilter {

  @Override
  protected OAuthToken createOAuthToken(String consumerKey) {
    return getConsumerDetailsService().createAccessToken(consumerKey);
  }

  @Override
  protected void validateOAuthParams(Map<String, String> oauthParams) throws BadCredentialsException {
    super.validateOAuthParams(oauthParams);

    String token = oauthParams.get(OAuthConsumerParameter.oauth_token.toString());
    if (token == null) {
      throw new BadCredentialsException(messages.getMessage("OAuthUnauthenticatedRequestTokenProcessingFilter.missingToken", "Missing token."));
    }
  }
}
