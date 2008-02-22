package org.springframework.security.oauth.provider;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.springframework.security.oauth.common.OAuthConsumerParameter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * Processing filter for requests to protected resources.
 *
 * @author Ryan Heaton
 */
public class ProtectedResourceProcessingFilter extends OAuthProcessingFilter {

  @Override
  protected void validateSignature(ConsumerDetails consumerDetails, HttpServletRequest request, Map<String, String> oauthParams) throws AuthenticationException {
    super.validateSignature(consumerDetails, request, oauthParams);

    if (!getTokenServices().isValidAccessToken(oauthParams.get(OAuthConsumerParameter.oauth_token.toString()), consumerDetails.getConsumerKey())) {
      throw new BadCredentialsException("Invalid access token.");
    }
  }

  protected void onValidSignature(ConsumerDetails consumerDetails, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    chain.doFilter(request, response);
  }

  @Override
  protected void validateOAuthParams(ConsumerDetails consumerDetails, Map<String, String> oauthParams) throws BadCredentialsException {
    super.validateOAuthParams(consumerDetails, oauthParams);

    String token = oauthParams.get(OAuthConsumerParameter.oauth_token.toString());
    if (token == null) {
      throw new BadCredentialsException(messages.getMessage("ProtectedResourceProcessingFilter.missingToken", "Missing auth token."));
    }
  }


}
