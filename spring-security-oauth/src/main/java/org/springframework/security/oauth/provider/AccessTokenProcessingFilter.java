package org.springframework.security.oauth.provider;

import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.AuthenticationException;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.OAuthToken;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Processing filter for handling a request for an OAuth access token.
 *
 * @author Ryan Heaton
 */
public class AccessTokenProcessingFilter extends UnauthenticatedRequestTokenProcessingFilter {

  @Override
  protected OAuthToken createOAuthToken(String consumerKey) {
    return getTokenServices().createAccessToken(consumerKey);
  }

  @Override
  protected void validateOAuthParams(ConsumerDetails consumerDetails, Map<String, String> oauthParams) throws BadCredentialsException {
    super.validateOAuthParams(consumerDetails, oauthParams);

    String token = oauthParams.get(OAuthConsumerParameter.oauth_token.toString());
    if (token == null) {
      throw new BadCredentialsException(messages.getMessage("AccessTokenProcessingFilter.missingToken", "Missing token."));
    }
  }

  @Override
  protected void validateSignature(ConsumerDetails consumerDetails, HttpServletRequest request, Map<String, String> oauthParams) throws AuthenticationException {
    super.validateSignature(consumerDetails, request, oauthParams);

    //after the signature is validated, make sure the request token is authorized.
    String token = oauthParams.get(OAuthConsumerParameter.oauth_token.toString());
    if (!getTokenServices().isAuthorizedRequestToken(token, consumerKey)) {
      throw new BadCredentialsException(messages.getMessage("AccessTokenProcessingFilter.unauthorizedRequestToken", "Unauthorized request token."));
    }
  }

  @Override
  protected void onNewTimestamp() throws AuthenticationException {
    throw new BadCredentialsException(messages.getMessage("AccessTokenProcessingFilter.timestampNotNew", "A new timestamp should not be used in a request for an access token."));
  }
}
