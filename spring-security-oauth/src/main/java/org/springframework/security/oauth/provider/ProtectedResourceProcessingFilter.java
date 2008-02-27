package org.springframework.security.oauth.provider;

import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.provider.token.OAuthAccessToken;
import org.springframework.security.oauth.provider.token.OAuthToken;

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

  protected void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    ConsumerAuthentication authentication = (ConsumerAuthentication) SecurityContextHolder.getContext().getAuthentication();
    OAuthToken authToken = getTokenServices().getToken(authentication.getConsumerCredentials().getToken());
    if (!authToken.isAccessToken()) {
      throw new IllegalStateException("Token should be an access token.");
    }
    else {
      GrantedAuthority[] grantedAuthorities = ((OAuthAccessToken) authToken).getGrantedAuthorities();
      authentication.grantAuthorities(grantedAuthorities);
    }
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
