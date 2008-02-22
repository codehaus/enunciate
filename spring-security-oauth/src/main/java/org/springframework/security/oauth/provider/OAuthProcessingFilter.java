package org.springframework.security.oauth.provider;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.util.Assert;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.OAuthToken;
import org.springframework.security.oauth.common.EmptyOAuthToken;
import org.springframework.security.oauth.common.signature.SignatureSecret;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethod;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethodFactory;
import org.springframework.security.oauth.common.signature.CoreOAuthSignatureMethodFactory;
import org.springframework.security.oauth.provider.nonce.OAuthNonceServices;
import org.springframework.security.oauth.provider.nonce.ExpiringTimestampNonceServices;
import org.springframework.security.oauth.provider.token.OAuthTokenServices;
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
 * OAuth processing filter. This filter should be applied to requests for OAuth protected resources (see OAuth Core 1.0).<br/><br/>
 *
 * 
 * @author Ryan Heaton
 */
public abstract class OAuthProcessingFilter implements Filter, InitializingBean, MessageSourceAware {
  
  private static final Log LOG = LogFactory.getLog(UnauthenticatedRequestTokenProcessingFilter.class);
  private final List<String> allowedMethods = new ArrayList<String>(Arrays.asList("GET", "POST"));
  private OAuthProcessingFilterEntryPoint authenticationEntryPoint = new OAuthProcessingFilterEntryPoint();
  protected MessageSourceAccessor messages = AcegiMessageSource.getAccessor();
  private String filterProcessesUrl = "/oauth_access_token";
  private OAuthProviderSupport providerSupport = new CoreOAuthProviderSupport();
  private OAuthSignatureMethodFactory signatureMethodFactory = new CoreOAuthSignatureMethodFactory();
  private OAuthNonceServices nonceServices = new ExpiringTimestampNonceServices();

  private OAuthTokenServices tokenServices;
  private ConsumerDetailsService consumerDetailsService;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(consumerDetailsService, "A consumer details service is required.");
    Assert.notNull(tokenServices, "OAuth token services are required.");
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

        String consumerKey = oauthParams.get(OAuthConsumerParameter.oauth_consumer_key.toString());
        if (consumerKey == null) {
          throw new BadCredentialsException(messages.getMessage("OAuthProcessingFilter.missingConsumerKey", "Missing consumer key."));
        }

        ConsumerDetails consumerDetails = getConsumerDetailsService().loadConsumerByConsumerKey(consumerKey);

        validateOAuthParams(consumerDetails, oauthParams);

        validateSignature(consumerDetails, request, oauthParams);

        onValidSignature(consumerDetails, request, response, chain);
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
   * Validate the signature of the request given the parameters.
   *
   * @param consumerDetails The consumer details.
   * @param request The request.
   * @param oauthParams The parameters.
   */
  protected void validateSignature(ConsumerDetails consumerDetails, HttpServletRequest request, Map<String, String> oauthParams) throws AuthenticationException {
    String token = oauthParams.get(OAuthConsumerParameter.oauth_token.toString());
    String signatureMethod = oauthParams.get(OAuthConsumerParameter.oauth_signature_method.toString());
    String signature = oauthParams.get(OAuthConsumerParameter.oauth_signature.toString());
    String signatureBaseString = getProviderSupport().getSignatureBaseString(request);

    SignatureSecret secret = consumerDetails.getSignatureSecret();
    OAuthToken authToken;
    if (token != null) {
      authToken = getTokenServices().getToken(token, consumerKey);
    }
    else {
      //verify the signature of an empty token if the token wasn't supplied in the request.
      authToken = new EmptyOAuthToken();
    }

    OAuthSignatureMethod method = getSignatureMethodFactory().getSignatureMethod(signatureMethod, secret, authToken);

    method.verify(signatureBaseString, signature);
  }

  /**
   * Logic executed on valid signature. Default implementation continues the chain.
   *
   * @param consumerDetails The consumer details.
   * @param request The request.
   * @param response The response
   * @param chain The filter chain.
   */
  protected abstract void onValidSignature(ConsumerDetails consumerDetails, HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException;

  /**
   * Validates the OAuth parameters for the given consumer. Base implementation validates only those parameters
   * that are required for all OAuth requests. This includes the nonce and timestamp, but not the signature.
   *
   * @param consumerDetails The consumer details.
   * @param oauthParams The OAuth parameters to validate.
   * @throws org.acegisecurity.BadCredentialsException If the OAuth parameters are invalid.
   */
  protected void validateOAuthParams(ConsumerDetails consumerDetails, Map<String, String> oauthParams) throws BadCredentialsException {
    String version = oauthParams.get(OAuthConsumerParameter.oauth_version.toString());
    if ((version != null) && (!"1.0".equals(version))) {
      throw new OAuthVersionUnsupportedException("Unsupported OAuth version: " + version);
    }

    String realm = oauthParams.get("realm");
    if ((realm != null) && (!realm.equals(this.authenticationEntryPoint.getRealmName()))) {
      throw new BadCredentialsException(messages.getMessage("OAuthProcessingFilter.incorrectRealm",
                                                      new Object[]{realm, this.getAuthenticationEntryPoint().getRealmName()},
                                                      "Response realm name '{0}' does not match system realm name of '{1}'"));
    }

    String signatureMethod = oauthParams.get(OAuthConsumerParameter.oauth_signature_method.toString());
    if (signatureMethod == null) {
      throw new BadCredentialsException(messages.getMessage("OAuthProcessingFilter.missingSignatureMethod", "Missing signature method."));
    }

    String signature = oauthParams.get(OAuthConsumerParameter.oauth_signature.toString());
    if (signature == null) {
      throw new BadCredentialsException(messages.getMessage("OAuthProcessingFilter.missingSignature", "Missing signature."));
    }

    String timestamp = oauthParams.get(OAuthConsumerParameter.oauth_timestamp.toString());
    if (timestamp == null) {
      throw new BadCredentialsException(messages.getMessage("OAuthProcessingFilter.missingTimestamp", "Missing timestamp."));
    }

    String nonce = oauthParams.get(OAuthConsumerParameter.oauth_nonce.toString());
    if (nonce == null) {
      throw new BadCredentialsException(messages.getMessage("OAuthProcessingFilter.missingNonce", "Missing nonce."));
    }

    try {
      if (getNonceServices().validateNonce(consumerDetails, Long.parseLong(timestamp), nonce)) {
        onNewTimestamp();
      }
    }
    catch (NumberFormatException e) {
      throw new BadCredentialsException(messages.getMessage("OAuthProcessingFilter.invalidTimestamp", new Object[] {timestamp}, "Timestamp must be a positive integer. Invalid value: {0}"));
    }
  }

  /**
   * Logic to be performed on a new timestamp.  The default behavior expects that the timestamp should not be new.
   *
   * @throws org.acegisecurity.AuthenticationException If the timestamp shouldn't be new.
   */
  protected void onNewTimestamp() throws AuthenticationException {
    throw new BadCredentialsException(messages.getMessage("OAuthProcessingFilter.timestampNotNew", "A new timestamp should not be used in a request for an access token."));
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
  public ConsumerDetailsService getConsumerDetailsService() {
    return consumerDetailsService;
  }

  /**
   * The consumer details service.
   *
   * @param consumerDetailsService The consumer details service.
   */
  public void setConsumerDetailsService(ConsumerDetailsService consumerDetailsService) {
    this.consumerDetailsService = consumerDetailsService;
  }

  /**
   * The nonce services.
   *
   * @return The nonce services.
   */
  public OAuthNonceServices getNonceServices() {
    return nonceServices;
  }

  /**
   * The nonce services.
   *
   * @param nonceServices The nonce services.
   */
  public void setNonceServices(OAuthNonceServices nonceServices) {
    this.nonceServices = nonceServices;
  }

  /**
   * Get the OAuth token services.
   *
   * @return The OAuth token services.
   */
  public OAuthTokenServices getTokenServices() {
    return tokenServices;
  }

  /**
   * The OAuth token services.
   *
   * @param tokenServices The OAuth token services.
   */
  public void setTokenServices(OAuthTokenServices tokenServices) {
    this.tokenServices = tokenServices;
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
