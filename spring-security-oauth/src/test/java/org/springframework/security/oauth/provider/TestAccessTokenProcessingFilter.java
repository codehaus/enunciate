package org.springframework.security.oauth.provider;

import static org.easymock.EasyMock.*;
import org.springframework.security.oauth.provider.token.OAuthTokenServices;
import org.springframework.security.oauth.provider.token.OAuthAccessToken;
import org.acegisecurity.AuthenticationException;

import junit.framework.TestCase;

/**
 * @author Ryan Heaton
 */
public class TestAccessTokenProcessingFilter extends TestCase {

  /**
   * tests creating the oauth token.
   */
  public void testCreateOAuthToken() throws Exception {
    ConsumerDetails consumerDetails = createMock(ConsumerDetails.class);
    ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
    ConsumerAuthentication authentication = new ConsumerAuthentication(consumerDetails, creds);
    OAuthTokenServices tokenServices = createMock(OAuthTokenServices.class);
    OAuthAccessToken token = createMock(OAuthAccessToken.class);

    AccessTokenProcessingFilter filter = new AccessTokenProcessingFilter();
    filter.setTokenServices(tokenServices);

    expect(tokenServices.createAccessToken("tok")).andReturn(token);
    replay(consumerDetails, tokenServices, token);
    assertSame(token, filter.createOAuthToken(authentication));
    verify(consumerDetails, tokenServices, token);
    reset(consumerDetails, tokenServices, token);
  }

  /**
   * tests the logic on a new timestamp.
   */
  public void testOnNewTimestamp() throws Exception {
    try {
      new AccessTokenProcessingFilter().onNewTimestamp();
      fail();
    }
    catch (InvalidOAuthParametersException e) {
      //fall through
    }
  }

}
