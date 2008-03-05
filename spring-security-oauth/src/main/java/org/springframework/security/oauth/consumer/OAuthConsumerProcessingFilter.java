package org.springframework.security.oauth.consumer;

import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.intercept.web.FilterInvocation;
import org.acegisecurity.intercept.web.FilterInvocationDefinitionSource;
import org.acegisecurity.ui.AuthenticationEntryPoint;
import org.acegisecurity.ui.savedrequest.SavedRequest;
import org.acegisecurity.util.PortResolver;
import org.acegisecurity.util.PortResolverImpl;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.oauth.common.UserNotAuthenticatedException;
import org.springframework.security.oauth.common.signature.CoreOAuthSignatureMethodFactory;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethodFactory;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;
import org.springframework.security.oauth.consumer.token.OAuthConsumerTokenServices;
import org.springframework.security.oauth.consumer.token.OAuthConsumerTokenServicesFactory;
import org.springframework.security.oauth.consumer.token.HttpSessionBasedTokenServicesFactory;
import org.springframework.security.oauth.provider.nonce.ExpiringTimestampNonceServices;
import org.springframework.security.oauth.provider.nonce.OAuthNonceServices;
import org.springframework.util.Assert;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;

/**
 * OAuth processing filter. This filter should be applied to requests for OAuth protected resources (see OAuth Core 1.0).<br/><br/>
 *
 * @author Ryan Heaton
 */
public class OAuthConsumerProcessingFilter implements Filter, InitializingBean, MessageSourceAware {

  public static final String ACCESS_TOKENS_DEFAULT_ATTRIBUTE = "OAUTH_ACCESS_TOKENS";

  private AuthenticationEntryPoint OAuthFailureEntryPoint;
  protected MessageSourceAccessor messages = AcegiMessageSource.getAccessor();
  private FilterInvocationDefinitionSource objectDefinitionSource;
  private OAuthConsumerSupport consumerSupport = new CoreOAuthConsumerSupport();
  private OAuthSignatureMethodFactory signatureMethodFactory = new CoreOAuthSignatureMethodFactory();
  private OAuthNonceServices nonceServices = new ExpiringTimestampNonceServices();
  private boolean requireAuthenticated = true;
  private String accessTokensRequestAttribute = ACCESS_TOKENS_DEFAULT_ATTRIBUTE;
  private PortResolver portResolver = new PortResolverImpl();

  private OAuthConsumerTokenServicesFactory tokenServicesFactory = new HttpSessionBasedTokenServicesFactory();
  private ProtectedResourceDetailsService protectedResourceDetailsService;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(OAuthFailureEntryPoint, "An entry point must be configured to handle the case of OAuth failure.");
    Assert.notNull(tokenServicesFactory, "OAuth token services factory is required.");
    Assert.notNull(protectedResourceDetailsService, "A protected resource details service is required.");
  }

  public void init(FilterConfig ignored) throws ServletException {
  }

  public void destroy() {
  }

  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    Set<String> accessTokenDeps = getAccessTokenDependencies(request, response, chain);
    if (!accessTokenDeps.isEmpty()) {
      try {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (requireAuthenticated && !authentication.isAuthenticated()) {
          throw new UserNotAuthenticatedException("Must be authenticated.");
        }

        OAuthConsumerTokenServices tokenServices = getTokenServicesFactory().getTokenServices(authentication, request);
        List<OAuthConsumerToken> tokens = new ArrayList<OAuthConsumerToken>();
        for (String dependency : accessTokenDeps) {
          OAuthConsumerToken token = tokenServices.getToken(dependency);
          if (token == null) {
            //obtain authorization.
            ProtectedResourceDetails details = getProtectedResourceDetailsService().loadProtectedResourceDetailsById(dependency);
            OAuthConsumerToken requestToken = getConsumerSupport().getUnauthorizedRequestToken(dependency);
            requestToken.setAccessToken(false);
            requestToken.setResourceId(dependency);
            tokenServices.storeToken(dependency, requestToken);
            String callbackURL = response.encodeRedirectURL(getCallbackURL(request));
            String redirect = getUserAuthorizationRedirectURL(details, requestToken, callbackURL);
            response.sendRedirect(redirect);
            return;
          }
          else {
            if (!token.isAccessToken()) {
              //authorize the request token and store it.
              token = getConsumerSupport().getAccessToken(token);
              token.setAccessToken(true);
              token.setResourceId(dependency);
              tokenServices.storeToken(dependency, token);
            }

            //token already authorized.
            tokens.add(token);
          }
        }

        request.setAttribute(getAccessTokensRequestAttribute(), tokens);
        chain.doFilter(request, response);
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
   * Get the callback URL for the specified request.
   *
   * @param request The request.
   * @return The callback URL.
   */
  protected String getCallbackURL(HttpServletRequest request) {
    return new SavedRequest(request, getPortResolver()).getFullRequestUrl();
  }

  /**
   * Get the URL to which to redirect the user for authorization of protected resources.
   *
   * @param details      The details of the protected resource.
   * @param requestToken The request token.
   * @param callbackURL  The callback URL.
   * @return The URL.
   */
  protected String getUserAuthorizationRedirectURL(ProtectedResourceDetails details, OAuthConsumerToken requestToken, String callbackURL) {
    try {
      String baseURL = details.getUserAuthorizationURL();
      StringBuilder builder = new StringBuilder(baseURL);
      char appendChar = baseURL.indexOf('?') < 0 ? '?' : '&';
      builder.append(appendChar).append("oauth_token=").append(URLEncoder.encode(requestToken.getValue(), "UTF-8"));
      builder.append("&oauth_callback=").append(URLEncoder.encode(callbackURL, "UTF-8"));
      return builder.toString();
    }
    catch (UnsupportedEncodingException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Common logic for OAuth failed.
   *
   * @param request  The request.
   * @param response The response.
   * @param failure  The failure.
   */
  protected void fail(HttpServletRequest request, HttpServletResponse response, AuthenticationException failure) throws IOException, ServletException {
    OAuthFailureEntryPoint.commence(request, response, failure);
  }

  /**
   * Loads the access token dependencies for the given request. This will be a set of {@link ProtectedResourceDetails#getId() resource ids}
   * for which an OAuth access token is required.
   *
   * @param request     The request.
   * @param response    The response
   * @param filterChain The filter chain
   * @return The access token dependencies (could be empty).
   */
  protected Set<String> getAccessTokenDependencies(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
    Set<String> deps = new TreeSet<String>();

    if (getObjectDefinitionSource() != null) {
      FilterInvocation invocation = new FilterInvocation(request, response, filterChain);
      ConfigAttributeDefinition attributeDefinition = getObjectDefinitionSource().getAttributes(invocation);
      Iterator attributes = attributeDefinition.getConfigAttributes();
      if (attributes != null) {
        while (attributes.hasNext()) {
          ConfigAttribute attribute = (ConfigAttribute) attributes.next();
          deps.add(attribute.getAttribute());
        }
      }
    }

    return deps;
  }

  /**
   * The protected resource details service.
   *
   * @return The protected resource details service.
   */
  public ProtectedResourceDetailsService getProtectedResourceDetailsService() {
    return protectedResourceDetailsService;
  }

  /**
   * The protected resource details service.
   *
   * @param protectedResourceDetailsService
   *         The protected resource details service.
   */
  public void setProtectedResourceDetailsService(ProtectedResourceDetailsService protectedResourceDetailsService) {
    this.protectedResourceDetailsService = protectedResourceDetailsService;
  }

  /**
   * The authentication entry point.
   *
   * @return The authentication entry point.
   */
  public AuthenticationEntryPoint getOAuthFailureEntryPoint() {
    return OAuthFailureEntryPoint;
  }

  /**
   * The authentication entry point.
   *
   * @param OAuthFailureEntryPoint The authentication entry point.
   */
  public void setOAuthFailureEntryPoint(AuthenticationEntryPoint OAuthFailureEntryPoint) {
    this.OAuthFailureEntryPoint = OAuthFailureEntryPoint;
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
   * Get the OAuth token services factory.
   *
   * @return The OAuth token services factory.
   */
  public OAuthConsumerTokenServicesFactory getTokenServicesFactory() {
    return tokenServicesFactory;
  }

  /**
   * The OAuth token services factory.
   *
   * @param tokenServicesFactory The OAuth token services factory.
   */
  public void setTokenServicesFactory(OAuthConsumerTokenServicesFactory tokenServicesFactory) {
    this.tokenServicesFactory = tokenServicesFactory;
  }

  /**
   * The filter invocation definition source.
   *
   * @return The filter invocation definition source.
   */
  public FilterInvocationDefinitionSource getObjectDefinitionSource() {
    return objectDefinitionSource;
  }

  /**
   * The filter invocation definition source.
   *
   * @param objectDefinitionSource The filter invocation definition source.
   */
  public void setObjectDefinitionSource(FilterInvocationDefinitionSource objectDefinitionSource) {
    this.objectDefinitionSource = objectDefinitionSource;
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
   * The OAuth consumer support.
   *
   * @return The OAuth consumer support.
   */
  public OAuthConsumerSupport getConsumerSupport() {
    return consumerSupport;
  }

  /**
   * The OAuth consumer support.
   *
   * @param consumerSupport The OAuth consumer support.
   */
  public void setConsumerSupport(OAuthConsumerSupport consumerSupport) {
    this.consumerSupport = consumerSupport;
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
   * Whether to require the current authentication to be authenticated.
   *
   * @return Whether to require the current authentication to be authenticated.
   */
  public boolean isRequireAuthenticated() {
    return requireAuthenticated;
  }

  /**
   * Whether to require the current authentication to be authenticated.
   *
   * @param requireAuthenticated Whether to require the current authentication to be authenticated.
   */
  public void setRequireAuthenticated(boolean requireAuthenticated) {
    this.requireAuthenticated = requireAuthenticated;
  }

  /**
   * The default request attribute into which the OAuth access tokens are stored.
   *
   * @return The default request attribute into which the OAuth access tokens are stored.
   */
  public String getAccessTokensRequestAttribute() {
    return accessTokensRequestAttribute;
  }

  /**
   * The default request attribute into which the OAuth access tokens are stored.
   *
   * @param accessTokensRequestAttribute The default request attribute into which the OAuth access tokens are stored.
   */
  public void setAccessTokensRequestAttribute(String accessTokensRequestAttribute) {
    this.accessTokensRequestAttribute = accessTokensRequestAttribute;
  }

  /**
   * The port resolver.
   *
   * @return The port resolver.
   */
  public PortResolver getPortResolver() {
    return portResolver;
  }

  /**
   * The port resolver.
   *
   * @param portResolver The port resolver.
   */
  public void setPortResolver(PortResolver portResolver) {
    this.portResolver = portResolver;
  }

}