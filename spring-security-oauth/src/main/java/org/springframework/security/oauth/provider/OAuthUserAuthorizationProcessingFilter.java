package org.springframework.security.oauth.provider;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.ui.AbstractProcessingFilter;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Processing filter for handling a request to authenticate an OAuth request token. According to the OAuth spec, the
 *
 * @author Ryan Heaton
 */
public class OAuthUserAuthorizationProcessingFilter extends AbstractProcessingFilter {

  private OAuthConsumerDetailsService consumerDetailsService;
  private String tokenIdParameterName = "oauth_token";
  private String callbackParameterName = "oauth_callback";

  public OAuthUserAuthorizationProcessingFilter() {
    setDefaultTargetUrl("/");
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.hasLength(getAuthenticationFailureUrl(), "authenticationFailureUrl must be provided.");
    Assert.notNull(getRememberMeServices());
    Assert.notNull(getConsumerDetailsService(), "A consumer details service must be provided.");
  }

  @Override
  protected void onPreAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
    if (request.getParameter(getTokenParameterName()) == null) {
      throw new BadCredentialsException("An OAuth token id is required.");
    }
  }

  public Authentication attemptAuthentication(HttpServletRequest request) throws AuthenticationException {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (!authentication.isAuthenticated()) {
      throw new UserNotAuthenticatedException("User must be authenticated before authorizing a request token.");
    }
    getConsumerDetailsService().authorizeRequestToken(request.getParameter(getTokenParameterName()));
    return authentication;
  }

  @Override
  protected String determineTargetUrl(HttpServletRequest request) {
    String callbackURL = request.getParameter(getCallbackParameterName());
    if (callbackURL != null) {
      char appendChar = '?';
      if (callbackURL.indexOf('?') > 0) {
        appendChar = '&';
      }
      StringBuilder url = new StringBuilder(callbackURL).append(appendChar).append("oauth_token=").append(request.getParameter(getTokenParameterName()));
      return url.toString();
    }
    else {
      return super.determineTargetUrl(request);
    }
  }

  public String getDefaultFilterProcessesUrl() {
    return "/oauth_authenticate_token";
  }

  /**
   * The name of the request parameter that supplies the token id.
   *
   * @return The name of the request parameter that supplies the token id.
   */
  public String getTokenParameterName() {
    return tokenIdParameterName;
  }

  /**
   * The name of the request parameter that supplies the token id.
   *
   * @param tokenIdParameterName The name of the request parameter that supplies the token id.
   */
  public void setTokenIdParameterName(String tokenIdParameterName) {
    this.tokenIdParameterName = tokenIdParameterName;
  }

  /**
   * The name of the request parameter that supplies the callback URL.
   *
   * @return The name of the request parameter that supplies the callback URL.
   */
  public String getCallbackParameterName() {
    return callbackParameterName;
  }

  /**
   * The name of the request parameter that supplies the callback URL.
   *
   * @param callbackParameterName The name of the request parameter that supplies the callback URL.
   */
  public void setCallbackParameterName(String callbackParameterName) {
    this.callbackParameterName = callbackParameterName;
  }

  /**
   * The consumer details service.
   *
   * @return The consumer details service.
   */
  public OAuthConsumerDetailsService getConsumerDetailsService() {
    return consumerDetailsService;
  }

  /**
   * The consumer details service.
   *
   * @param consumerDetailsService The consumer details service.
   */
  public void setConsumerDetailsService(OAuthConsumerDetailsService consumerDetailsService) {
    this.consumerDetailsService = consumerDetailsService;
  }
}