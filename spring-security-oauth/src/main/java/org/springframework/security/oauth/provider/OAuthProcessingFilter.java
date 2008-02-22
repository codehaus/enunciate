package org.springframework.security.oauth.provider;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.util.Assert;
import org.springframework.security.oauth.common.signature.SignatureSecret;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethod;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethodFactory;
import org.springframework.security.oauth.common.signature.CoreOAuthSignatureMethodFactory;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.AcegiMessageSource;
import org.acegisecurity.context.SecurityContextHolder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Base OAuth processing filter.
 *
 * @author Ryan Heaton
 */
public abstract class OAuthProcessingFilter implements Filter, InitializingBean, MessageSourceAware {

  private static final Log LOG = LogFactory.getLog(OAuthTokenProcessingFilter.class);
  private final List<String> allowedMethods = new ArrayList<String>(Arrays.asList("GET", "POST"));
  private OAuthProcessingFilterEntryPoint authenticationEntryPoint = new OAuthProcessingFilterEntryPoint();
  protected MessageSourceAccessor messages = AcegiMessageSource.getAccessor();
  private OAuthConsumerDetailsService consumerDetailsService;
  private String filterProcessesUrl = "/oauth_access_token";
  private OAuthProviderSupport providerSupport = new CoreOAuthProviderSupport();
  private OAuthSignatureMethodFactory signatureMethodFactory = new CoreOAuthSignatureMethodFactory();

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(consumerDetailsService, "A consumer details service is required");
  }

  public void init(FilterConfig ignored) throws ServletException {
  }

  public void destroy() {
  }

  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    if (requiresAuthentication(request)) {
      if (!allowedMethods.contains(request.getMethod().toUpperCase())) {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        return;
      }

      try {
        Map<String, String> oauthParams = getProviderSupport().parseParameters(request);

        validateOAuthParams(oauthParams);

        String consumerKey = oauthParams.get(OAuthConsumerParameter.oauth_consumer_key.toString());
        String token = oauthParams.get(OAuthConsumerParameter.oauth_token.toString());
        SignatureSecret secret = readSignatureSecret(consumerKey, token);
        String signatureMethod = oauthParams.get(OAuthConsumerParameter.oauth_signature_method.toString());
        String signature = oauthParams.get(OAuthConsumerParameter.oauth_signature.toString());
        String signatureBaseString = getProviderSupport().getSignatureBaseString(request);
        OAuthSignatureMethod method = getSignatureMethodFactory().getSignatureMethod(signatureMethod, secret);
        method.verify(signatureBaseString, signature);
        onValidSignature(oauthParams, request, response, chain);
      }
      catch (AuthenticationException ae) {
        fail(request, response, ae);
      }
    }
    else {
      chain.doFilter(servletRequest, servletResponse);
    }
  }

  /**
   * Logic executed on valid signature. Default implementation continues the chain.
   *
   * @param params The oauth params.
   * @param request The request.
   * @param response The response
   * @param chain The filter chain.
   */
  protected void onValidSignature(Map<String, String> params, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    chain.doFilter(request, response);
  }

  /**
   * Read the signature secret for the specified consumer key and OAuth token.
   *
   * @param consumerKey The consumer key.
   * @param token The OAuth token.
   * @return the signature secret.
   */
  protected SignatureSecret readSignatureSecret(String consumerKey, String token) {
    return getConsumerDetailsService().getSignatureSecret(consumerKey, token);
  }

  /**
   * Validates the OAuth parameters.
   *
   * @param oauthParams The OAuth parameters to validate.
   * @throws org.acegisecurity.BadCredentialsException If the OAuth parameters are invalid.
   */
  protected void validateOAuthParams(Map<String, String> oauthParams) throws BadCredentialsException {
    String version = oauthParams.get(OAuthConsumerParameter.oauth_version.toString());
    if ((version != null) && (!"1.0".equals(version))) {
      throw new OAuthVersionUnsupportedException("Unsupported OAuth version: " + version);
    }

    String realm = oauthParams.get("realm");
    if ((realm != null) && (!realm.equals(this.authenticationEntryPoint.getRealmName()))) {
      throw new BadCredentialsException(messages.getMessage("OAuthUnauthenticatedRequestTokenProcessingFilter.incorrectRealm",
                                                      new Object[]{realm, this.getAuthenticationEntryPoint().getRealmName()},
                                                      "Response realm name '{0}' does not match system realm name of '{1}'"));
    }

    String consumerKey = oauthParams.get(OAuthConsumerParameter.oauth_consumer_key.toString());
    if (consumerKey == null) {
      throw new BadCredentialsException(messages.getMessage("OAuthUnauthenticatedRequestTokenProcessingFilter.missingConsumerKey", "Missing consumer key."));
    }

    String signatureMethod = oauthParams.get(OAuthConsumerParameter.oauth_signature_method.toString());
    if (signatureMethod == null) {
      throw new BadCredentialsException(messages.getMessage("OAuthUnauthenticatedRequestTokenProcessingFilter.missingSignatureMethod", "Missing signature method."));
    }

    String signature = oauthParams.get(OAuthConsumerParameter.oauth_signature.toString());
    if (signature == null) {
      throw new BadCredentialsException(messages.getMessage("OAuthUnauthenticatedRequestTokenProcessingFilter.missingSignature", "Missing signature."));
    }

    String timestamp = oauthParams.get(OAuthConsumerParameter.oauth_timestamp.toString());
    if (timestamp == null) {
      throw new BadCredentialsException(messages.getMessage("OAuthUnauthenticatedRequestTokenProcessingFilter.missingTimestamp", "Missing timestamp."));
    }

    String nonce = oauthParams.get(OAuthConsumerParameter.oauth_nonce.toString());
    if (nonce == null) {
      throw new BadCredentialsException(messages.getMessage("OAuthUnauthenticatedRequestTokenProcessingFilter.missingNonce", "Missing nonce."));
    }

    try {
      getConsumerDetailsService().validateNonce(consumerKey, Long.parseLong(timestamp), nonce);
    }
    catch (NumberFormatException e) {
      throw new BadCredentialsException(messages.getMessage("OAuthUnauthenticatedRequestTokenProcessingFilter.invalidTimestamp", new Object[] {timestamp}, "Timestamp must be a positive integer. Invalid value: {0}"));
    }
  }

  /**
   * Common logic for OAuth failed.
   *
   * @param request The request.
   * @param response The response.
   * @param failure The failure.
   */
  protected void fail(ServletRequest request, ServletResponse response, AuthenticationException failure) throws IOException, ServletException {
    SecurityContextHolder.getContext().setAuthentication(null);

    if (LOG.isDebugEnabled()) {
      LOG.debug(failure);
    }

    authenticationEntryPoint.commence(request, response, failure);
  }

  /**
   * Whether this filter is configured to process the specified request.
   *
   * @param request The request.
   * @return Whether this filter is configured to process the specified request.
   */
  protected boolean requiresAuthentication(HttpServletRequest request) {
    //copied from org.acegisecurity.ui.AbstractProcessingFilter.requiresAuthentication
    String uri = request.getRequestURI();
    int pathParamIndex = uri.indexOf(';');

    if (pathParamIndex > 0) {
      // strip everything after the first semi-colon
      uri = uri.substring(0, pathParamIndex);
    }

    if ("".equals(request.getContextPath())) {
      return uri.endsWith(filterProcessesUrl);
    }

    return uri.endsWith(request.getContextPath() + filterProcessesUrl);
  }

  /**
   * The authentication entry point.
   *
   * @return The authentication entry point.
   */
  public OAuthProcessingFilterEntryPoint getAuthenticationEntryPoint() {
    return authenticationEntryPoint;
  }

  /**
   * The authentication entry point.
   *
   * @param authenticationEntryPoint The authentication entry point.
   */
  public void setAuthenticationEntryPoint(OAuthProcessingFilterEntryPoint authenticationEntryPoint) {
    this.authenticationEntryPoint = authenticationEntryPoint;
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

  /**
   * The URL for which this filter will be applied.
   *
   * @return The URL for which this filter will be applied.
   */
  public String getFilterProcessesUrl() {
    return filterProcessesUrl;
  }

  /**
   * The URL for which this filter will be applied.
   *
   * @param filterProcessesUrl The URL for which this filter will be applied.
   */
  public void setFilterProcessesUrl(String filterProcessesUrl) {
    this.filterProcessesUrl = filterProcessesUrl;
  }

  /**
   * Set the message source.
   *
   * @param messageSource The message source.
   */
  public void setMessageSource(MessageSource messageSource) {
    this.messages = new MessageSourceAccessor(messageSource);
  }

  /**
   * The OAuth provider support.
   *
   * @return The OAuth provider support.
   */
  public OAuthProviderSupport getProviderSupport() {
    return providerSupport;
  }

  /**
   * The OAuth provider support.
   *
   * @param providerSupport The OAuth provider support.
   */
  public void setProviderSupport(OAuthProviderSupport providerSupport) {
    this.providerSupport = providerSupport;
  }

  /**
   * The OAuth signature method factory.
   *
   * @return The OAuth signature method factory.
   */
  public OAuthSignatureMethodFactory getSignatureMethodFactory() {
    return signatureMethodFactory;
  }

  /**
   * The OAuth signature method factory.
   *
   * @param signatureMethodFactory The OAuth signature method factory.
   */
  public void setSignatureMethodFactory(OAuthSignatureMethodFactory signatureMethodFactory) {
    this.signatureMethodFactory = signatureMethodFactory;
  }

  /**
   * The allowed set of HTTP methods.
   *
   * @param allowedMethods The allowed set of methods.
   */
  public void setAllowedMethods(List<String> allowedMethods) {
    this.allowedMethods.clear();
    if (allowedMethods != null) {
      for (String allowedMethod : allowedMethods) {
        this.allowedMethods.add(allowedMethod.toUpperCase());
      }
    }
  }
}
