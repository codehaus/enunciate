package org.springframework.security.oauth.provider;

import static org.easymock.EasyMock.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.springframework.security.oauth.provider.token.OAuthTokenServices;
import org.springframework.security.oauth.provider.token.OAuthAccessToken;

import junit.framework.TestCase;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.FilterChain;

/**
 * @author Ryan Heaton
 */
public class TestProtectedResourceProcessingFilter extends TestCase {

  /**
   * test onValidSignature
   */
  public void testOnValidSignature() throws Exception {
    ProtectedResourceProcessingFilter filter = new ProtectedResourceProcessingFilter();
    HttpServletRequest request = createMock(HttpServletRequest.class);
    HttpServletResponse response = createMock(HttpServletResponse.class);
    FilterChain chain = createMock(FilterChain.class);
    ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
    ConsumerAuthentication authentication = new ConsumerAuthentication(null, creds);
    authentication.setAuthenticated(true);
    SecurityContextHolder.getContext().setAuthentication(authentication);
    OAuthTokenServices tokenServices = createMock(OAuthTokenServices.class);
    OAuthAccessToken token = createMock(OAuthAccessToken.class);
    filter.setTokenServices(tokenServices);

    expect(tokenServices.getToken("tok")).andReturn(token);
    expect(token.isAccessToken()).andReturn(true);
    GrantedAuthority[] tokenAuthorities = { new GrantedAuthorityImpl("role1"), new GrantedAuthorityImpl("role2") };
    expect(token.getGrantedAuthorities()).andReturn(tokenAuthorities);
    chain.doFilter(request, response);
    replay(request, response, chain, tokenServices, token);
    filter.onValidSignature(request, response, chain);
    assertSame(tokenAuthorities, authentication.grantedAuthorities);
    verify(request, response, chain, tokenServices, token);
    reset(request, response, chain, tokenServices, token);

    SecurityContextHolder.getContext().setAuthentication(null);
  }

}
