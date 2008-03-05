package org.springframework.security.oauth.consumer.token;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.ui.WebAuthenticationDetails;

import javax.servlet.http.HttpSession;

/**
 * Stores the access tokens, etc. in the HTTP session.
 *
 * @author Ryan Heaton
 */
public class HttpSessionBasedTokenServices implements OAuthConsumerTokenServices {

  public static final String KEY_PREFIX = "OAUTH_TOKEN";

  public OAuthConsumerToken getToken(String resourceId, Authentication authentication) throws AuthenticationException {
    HttpSession session = loadHttpSession(authentication);
    return null;
  }

  private HttpSession loadHttpSession(Authentication authentication) {
    WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
    return details.;
  }

  public void storeToken(String resourceId, Authentication authentication, OAuthConsumerToken token) {
  }
}
