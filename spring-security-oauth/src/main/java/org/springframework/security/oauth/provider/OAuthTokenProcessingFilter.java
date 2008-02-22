package org.springframework.security.oauth.provider;

import org.springframework.security.oauth.common.OAuthCodec;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.OAuthProviderParameter;
import org.springframework.security.oauth.common.OAuthToken;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * Processing filter for handling a request for an OAuth token. The default implementation writes out
 * the response for a new unauthenticated request token.
 *
 * @author Ryan Heaton
 */
public class OAuthTokenProcessingFilter extends OAuthProcessingFilter {

  protected void onValidSignature(Map<String, String> params, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException {
    //signature is verified; create the token, send the response.
    OAuthToken authToken = createOAuthToken(params.get(OAuthConsumerParameter.oauth_consumer_key.toString()));
    String tokenName = OAuthCodec.oauthEncode(OAuthProviderParameter.oauth_token.toString());
    String tokenValue = OAuthCodec.oauthEncode(authToken.getValue());
    String secretName = OAuthCodec.oauthEncode(OAuthProviderParameter.oauth_token_secret.toString());
    String secretValue = OAuthCodec.oauthEncode(authToken.getSecret());
    StringBuilder responseValue = new StringBuilder(tokenName).append('=').append(tokenValue);
    responseValue.append(secretName).append('=').append(secretValue);
    response.setContentType("application/x-www-form-urlencoded");
    response.getWriter().print(responseValue.toString());
    response.flushBuffer();
  }

  /**
   * Create the OAuth token for the specified consumer key.
   *
   * @param consumerKey The consumer key.
   * @return The OAuth token.
   */
  protected OAuthToken createOAuthToken(String consumerKey) {
    return getConsumerDetailsService().createUnauthenticatedToken(consumerKey);
  }

}