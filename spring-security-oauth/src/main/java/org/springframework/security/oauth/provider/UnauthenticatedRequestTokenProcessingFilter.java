package org.springframework.security.oauth.provider;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthCodec;
import org.springframework.security.oauth.common.OAuthProviderParameter;
import org.springframework.security.oauth.provider.token.OAuthToken;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Processing filter for handling a request for an OAuth token. The default implementation assumes a request for a new
 * unauthenticated request token.
 *
 * @author Ryan Heaton
 */
public class UnauthenticatedRequestTokenProcessingFilter extends OAuthProcessingFilter {

  protected void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException {
    //signature is verified; create the token, send the response.
    ConsumerAuthentication authentication = (ConsumerAuthentication) SecurityContextHolder.getContext().getAuthentication();
    OAuthToken authToken = createOAuthToken(authentication);
    if (!authToken.getConsumerKey().equals(authentication.getConsumerDetails().getConsumerKey())) {
      throw new IllegalStateException("The consumer key associated with the created auth token is not valid for the authenticated consumer.");
    }

    String tokenName = OAuthCodec.oauthEncode(OAuthProviderParameter.oauth_token.toString());
    String tokenValue = OAuthCodec.oauthEncode(authToken.getValue());
    String secretName = OAuthCodec.oauthEncode(OAuthProviderParameter.oauth_token_secret.toString());
    String secretValue = OAuthCodec.oauthEncode(authToken.getSecret());
    StringBuilder responseValue = new StringBuilder(tokenName).append('=').append(tokenValue);
    responseValue.append('&');
    responseValue.append(secretName).append('=').append(secretValue);
    response.setContentType("application/x-www-form-urlencoded");
    response.getWriter().print(responseValue.toString());
    response.flushBuffer();
  }

  @Override
  protected void onNewTimestamp() throws AuthenticationException {
    //no-op. A new timestamp should be supplied for a request for a new unauthenticated request token.
  }

  /**
   * Create the OAuth token for the specified consumer key.
   *
   * @param authentication The authentication request.
   * @return The OAuth token.
   */
  protected OAuthToken createOAuthToken(ConsumerAuthentication authentication) {
    return getTokenServices().createUnauthorizedRequestToken(authentication.getConsumerDetails().getConsumerKey());
  }

}