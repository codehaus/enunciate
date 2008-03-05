package org.springframework.security.oauth.provider;

import junit.framework.TestCase;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import static org.easymock.EasyMock.*;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethod;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethodFactory;
import org.springframework.security.oauth.common.signature.SignatureSecret;
import org.springframework.security.oauth.provider.nonce.OAuthNonceServices;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Tests the basic processing filter logic.
 *
 * @author Ryan Heaton
 */
public class TestOAuthProcessingFilter extends TestCase {

  /**
   * tests do filter.
   */
  public void testDoFilter() throws Exception {
    final boolean[] triggers = new boolean[2];
    Arrays.fill(triggers, false);
    OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter() {
      @Override
      protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        return true;
      }

      protected void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        chain.doFilter(null, null);
      }

      @Override
      protected void validateOAuthParams(ConsumerDetails consumerDetails, Map<String, String> oauthParams) throws BadCredentialsException {
        triggers[0] = true;
      }

      @Override
      protected void validateSignature(ConsumerAuthentication authentication) throws AuthenticationException {
        triggers[1] = true;
      }

      @Override
      protected void fail(HttpServletRequest request, HttpServletResponse response, AuthenticationException failure) throws IOException, ServletException {
        throw failure;
      }

      @Override
      protected Object createDetails(HttpServletRequest request, ConsumerDetails consumerDetails) {
        return null;
      }

      @Override
      protected void resetPreviousAuthentication(Authentication previousAuthentication) {
        //no-op
      }
    };

    OAuthProviderSupport providerSupport = createMock(OAuthProviderSupport.class);
    ConsumerDetailsService consumerDetailsService = createMock(ConsumerDetailsService.class);
    OAuthNonceServices nonceServices = createMock(OAuthNonceServices.class);
    OAuthSignatureMethodFactory signatureFactory = createMock(OAuthSignatureMethodFactory.class);
    OAuthProviderTokenServices tokenServices = createMock(OAuthProviderTokenServices.class);

    filter.setProviderSupport(providerSupport);
    filter.setConsumerDetailsService(consumerDetailsService);
    filter.setNonceServices(nonceServices);
    filter.setSignatureMethodFactory(signatureFactory);
    filter.setTokenServices(tokenServices);

    HttpServletRequest request = createMock(HttpServletRequest.class);
    HttpServletResponse response = createMock(HttpServletResponse.class);
    FilterChain filterChain = createMock(FilterChain.class);

    expect(request.getMethod()).andReturn("DELETE");
    response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    replay(request, response, filterChain, providerSupport, consumerDetailsService, nonceServices, signatureFactory, tokenServices);
    filter.doFilter(request, response, filterChain);
    verify(request, response, filterChain, providerSupport, consumerDetailsService, nonceServices, signatureFactory, tokenServices);
    reset(request, response, filterChain, providerSupport, consumerDetailsService, nonceServices, signatureFactory, tokenServices);
    assertFalse(triggers[0]);
    assertFalse(triggers[1]);
    Arrays.fill(triggers, false);

    expect(request.getMethod()).andReturn("GET");
    HashMap<String, String> requestParams = new HashMap<String, String>();
    expect(providerSupport.parseParameters(request)).andReturn(requestParams);
    replay(request, response, filterChain, providerSupport, consumerDetailsService, nonceServices, signatureFactory, tokenServices);
    try {
      filter.doFilter(request, response, filterChain);
      fail("should have required a consumer key.");
    }
    catch (BadCredentialsException e) {
      verify(request, response, filterChain, providerSupport, consumerDetailsService, nonceServices, signatureFactory, tokenServices);
      reset(request, response, filterChain, providerSupport, consumerDetailsService, nonceServices, signatureFactory, tokenServices);
      assertFalse(triggers[0]);
      assertFalse(triggers[1]);
      Arrays.fill(triggers, false);
    }

    expect(request.getMethod()).andReturn("GET");
    requestParams = new HashMap<String, String>();
    requestParams.put(OAuthConsumerParameter.oauth_consumer_key.toString(), "consumerKey");
    expect(providerSupport.parseParameters(request)).andReturn(requestParams);
    ConsumerDetails consumerDetails = createMock(ConsumerDetails.class);
    expect(consumerDetailsService.loadConsumerByConsumerKey("consumerKey")).andReturn(consumerDetails);
    requestParams.put(OAuthConsumerParameter.oauth_token.toString(), "tokenvalue");
    requestParams.put(OAuthConsumerParameter.oauth_signature_method.toString(), "methodvalue");
    requestParams.put(OAuthConsumerParameter.oauth_signature.toString(), "signaturevalue");
    expect(providerSupport.getSignatureBaseString(request)).andReturn("sigbasestring");
    filterChain.doFilter(null, null);
    replay(request, response, filterChain, providerSupport, consumerDetailsService, nonceServices, signatureFactory, tokenServices, consumerDetails);
    filter.doFilter(request, response, filterChain);
    ConsumerAuthentication authentication = (ConsumerAuthentication) SecurityContextHolder.getContext().getAuthentication();
    assertSame(consumerDetails, authentication.getConsumerDetails());
    assertEquals("tokenvalue", authentication.getConsumerCredentials().getToken());
    assertEquals("methodvalue", authentication.getConsumerCredentials().getSignatureMethod());
    assertEquals("signaturevalue", authentication.getConsumerCredentials().getSignature());
    assertEquals("sigbasestring", authentication.getConsumerCredentials().getSignatureBaseString());
    assertEquals("consumerKey", authentication.getConsumerCredentials().getConsumerKey());
    assertTrue(authentication.isSignatureValidated());
    verify(request, response, filterChain, providerSupport, consumerDetailsService, nonceServices, signatureFactory, tokenServices, consumerDetails);
    reset(request, response, filterChain, providerSupport, consumerDetailsService, nonceServices, signatureFactory, tokenServices, consumerDetails);
    SecurityContextHolder.getContext().setAuthentication(null);
    assertTrue(triggers[0]);
    assertTrue(triggers[1]);
    Arrays.fill(triggers, false);
  }

  /**
   * tests validation of the params.
   */
  public void testValidateParams() throws Exception {
    OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter() {
      protected void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
      }
    };

    ConsumerDetails consumerDetails = createMock(ConsumerDetails.class);
    HashMap<String, String> params = new HashMap<String, String>();

    params.put(OAuthConsumerParameter.oauth_version.toString(), "1.1");
    replay(consumerDetails);
    try {
      filter.validateOAuthParams(consumerDetails, params);
      fail("should have thrown a bad credentials.");
    }
    catch (OAuthVersionUnsupportedException e) {
      verify(consumerDetails);
      reset(consumerDetails);
      params.remove(OAuthConsumerParameter.oauth_version.toString());
    }

    filter.getAuthenticationEntryPoint().setRealmName("anywho");
    params.put("realm", "hello");
    replay(consumerDetails);
    try {
      filter.validateOAuthParams(consumerDetails, params);
      fail("should have thrown a bad credentials.");
    }
    catch (InvalidOAuthParametersException e) {
      verify(consumerDetails);
      reset(consumerDetails);
    }

    params.put("realm", "anywho");
    replay(consumerDetails);
    try {
      filter.validateOAuthParams(consumerDetails, params);
      fail("should have thrown a bad credentials for missing signature method.");
    }
    catch (InvalidOAuthParametersException e) {
      verify(consumerDetails);
      reset(consumerDetails);
    }

    params.remove("realm");
    params.put(OAuthConsumerParameter.oauth_signature_method.toString(), "sigmethod");
    replay(consumerDetails);
    try {
      filter.validateOAuthParams(consumerDetails, params);
      fail("should have thrown a bad credentials for missing signature.");
    }
    catch (InvalidOAuthParametersException e) {
      verify(consumerDetails);
      reset(consumerDetails);
    }

    params.remove("realm");
    params.put(OAuthConsumerParameter.oauth_signature_method.toString(), "sigmethod");
    params.put(OAuthConsumerParameter.oauth_signature.toString(), "value");
    replay(consumerDetails);
    try {
      filter.validateOAuthParams(consumerDetails, params);
      fail("should have thrown a bad credentials for missing timestamp.");
    }
    catch (InvalidOAuthParametersException e) {
      verify(consumerDetails);
      reset(consumerDetails);
    }

    params.remove("realm");
    params.put(OAuthConsumerParameter.oauth_signature_method.toString(), "sigmethod");
    params.put(OAuthConsumerParameter.oauth_signature.toString(), "value");
    params.put(OAuthConsumerParameter.oauth_timestamp.toString(), "value");
    replay(consumerDetails);
    try {
      filter.validateOAuthParams(consumerDetails, params);
      fail("should have thrown a bad credentials for missing nonce.");
    }
    catch (InvalidOAuthParametersException e) {
      verify(consumerDetails);
      reset(consumerDetails);
    }

    params.remove("realm");
    params.put(OAuthConsumerParameter.oauth_signature_method.toString(), "sigmethod");
    params.put(OAuthConsumerParameter.oauth_signature.toString(), "value");
    params.put(OAuthConsumerParameter.oauth_timestamp.toString(), "value");
    params.put(OAuthConsumerParameter.oauth_nonce.toString(), "value");
    replay(consumerDetails);
    try {
      filter.validateOAuthParams(consumerDetails, params);
      fail("should have thrown a bad credentials for bad timestamp.");
    }
    catch (InvalidOAuthParametersException e) {
      verify(consumerDetails);
      reset(consumerDetails);
    }

    OAuthNonceServices nonceServices = createMock(OAuthNonceServices.class);
    filter.setNonceServices(nonceServices);
    params.remove("realm");
    params.put(OAuthConsumerParameter.oauth_signature_method.toString(), "sigmethod");
    params.put(OAuthConsumerParameter.oauth_signature.toString(), "value");
    params.put(OAuthConsumerParameter.oauth_timestamp.toString(), "1111111");
    params.put(OAuthConsumerParameter.oauth_nonce.toString(), "value");
    expect(nonceServices.validateNonce(consumerDetails, 1111111L, "value")).andReturn(true);
    replay(consumerDetails, nonceServices);
    try {
      filter.validateOAuthParams(consumerDetails, params);
      fail("should have thrown a bad credentials for new timestamp.");
    }
    catch (InvalidOAuthParametersException e) {
      verify(consumerDetails, nonceServices);
      reset(consumerDetails, nonceServices);
    }

    filter.setNonceServices(nonceServices);
    params.remove("realm");
    params.put(OAuthConsumerParameter.oauth_signature_method.toString(), "sigmethod");
    params.put(OAuthConsumerParameter.oauth_signature.toString(), "value");
    params.put(OAuthConsumerParameter.oauth_timestamp.toString(), "1111111");
    params.put(OAuthConsumerParameter.oauth_nonce.toString(), "value");
    expect(nonceServices.validateNonce(consumerDetails, 1111111L, "value")).andReturn(false);
    replay(consumerDetails, nonceServices);
    filter.validateOAuthParams(consumerDetails, params);
    verify(consumerDetails, nonceServices);
    reset(consumerDetails, nonceServices);
  }

  /**
   * test validating the signature.
   */
  public void testValidateSignature() throws Exception {
    OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter() {
      protected void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
      }
    };

    ConsumerDetails details = createMock(ConsumerDetails.class);
    SignatureSecret secret = createMock(SignatureSecret.class);
    OAuthProviderTokenServices tokenServices = createMock(OAuthProviderTokenServices.class);
    OAuthProviderToken token = createMock(OAuthProviderToken.class);
    OAuthSignatureMethodFactory sigFactory = createMock(OAuthSignatureMethodFactory.class);
    OAuthSignatureMethod sigMethod = createMock(OAuthSignatureMethod.class);

    ConsumerCredentials credentials = new ConsumerCredentials("id", "sig", "method", "base", "token");
    ConsumerAuthentication authentication = new ConsumerAuthentication(details, credentials);
    expect(details.getSignatureSecret()).andReturn(secret);
    filter.setTokenServices(tokenServices);
    expect(tokenServices.getToken("token")).andReturn(token);
    filter.setSignatureMethodFactory(sigFactory);
    expect(sigFactory.getSignatureMethod("method", secret, token.getSecret())).andReturn(sigMethod);
    sigMethod.verify("base", "sig");

    replay(details, secret, tokenServices, token,  sigFactory, sigMethod);
    filter.validateSignature(authentication);
    verify(details, secret, tokenServices, token,  sigFactory, sigMethod);
    reset(details, secret, tokenServices, token,  sigFactory, sigMethod);

  }

}
