package org.springframework.security.oauth.provider;

import org.acegisecurity.ui.digestauth.NonceExpiredException;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.util.StringSplitUtils;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.util.StringUtils;
import org.springframework.util.Assert;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.beans.factory.InitializingBean;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.*;
import java.util.*;
import java.io.IOException;

/**
 * Processing filter for handling a request for an OAuth unauthenticated request token per OAuth Core 1.0, 6.1.1.
 *
 * @author Ryan Heaton
 */
public class OAuthUnauthenticatedRequestTokenProcessingFilter implements Filter, InitializingBean, MessageSourceAware {

  private static final Log LOG = LogFactory.getLog(OAuthUnauthenticatedRequestTokenProcessingFilter.class);

  private final List<String> allowedMethods = new ArrayList<String>(Arrays.asList("GET", "POST"));
  private OAuthProcessingFilterEntryPoint authenticationEntryPoint = new OAuthProcessingFilterEntryPoint();
  private MessageSourceAccessor messages = AcegiMessageSource.getAccessor();
  private OAuthConsumerDetailsService consumerDetailsService;
  private String filterProcessesUrl = "/oauth_request_token";
  private OAuthProviderSupport providerSupport = new CoreOAuthProviderSupport();

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
        Map<String, String> oauthParams = this.providerSupport.parseParameters(request);
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
          throw new BadCredentialsException(messages.getMessage("OAuthUnauthenticatedRequestTokenProcessingFilter.invalidTimestamp", new Object[] { timestamp }, "Timestamp must be a positive integer. Invalid value: {0}"));
        }


        if ((header != null) && header.startsWith("Digest ")) {
          String section212response = header.substring(7);

          String[] headerEntries = StringSplitUtils.splitIgnoringQuotes(section212response, ',');
          Map headerMap = StringSplitUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"");

          String username = (String) headerMap.get("username");
          String realm = (String) headerMap.get("realm");
          String nonce = (String) headerMap.get("nonce");
          String uri = (String) headerMap.get("uri");
          String responseDigest = (String) headerMap.get("response");
          String qop = (String) headerMap.get("qop"); // RFC 2617 extension
          String nc = (String) headerMap.get("nc"); // RFC 2617 extension
          String cnonce = (String) headerMap.get("cnonce"); // RFC 2617 extension

          // Check all required parameters were supplied (ie RFC 2069)
          if ((username == null) || (realm == null) || (nonce == null) || (uri == null) || (servletResponse == null)) {
            if (LOG.isDebugEnabled()) {
              LOG.debug("extracted username: '" + username + "'; realm: '" + username + "'; nonce: '"
                + username + "'; uri: '" + username + "'; response: '" + username + "'");
            }

            fail(servletRequest, servletResponse,
                 new BadCredentialsException(messages.getMessage("DigestProcessingFilter.missingMandatory",
                                                                 new Object[]{section212response}, "Missing mandatory digest value; received header {0}")));

            return;
          }

          // Check all required parameters for an "auth" qop were supplied (ie RFC 2617)
          if ("auth".equals(qop)) {
            if ((nc == null) || (cnonce == null)) {
              if (LOG.isDebugEnabled()) {
                LOG.debug("extracted nc: '" + nc + "'; cnonce: '" + cnonce + "'");
              }

              fail(servletRequest, servletResponse,
                   new BadCredentialsException(messages.getMessage("DigestProcessingFilter.missingAuth",
                                                                   new Object[]{section212response}, "Missing mandatory digest value; received header {0}")));

              return;
            }
          }

          // Check realm name equals what we expected
          if (!this.getAuthenticationEntryPoint().getRealmName().equals(realm)) {
            fail(servletRequest, servletResponse,
                 );

            return;
          }

          // Check nonce was a Base64 encoded (as sent by DigestProcessingFilterEntryPoint)
          if (!Base64.isArrayByteBase64(nonce.getBytes())) {
            fail(servletRequest, servletResponse,
                 new BadCredentialsException(messages.getMessage("DigestProcessingFilter.nonceEncoding",
                                                                 new Object[]{nonce}, "Nonce is not encoded in Base64; received nonce {0}")));

            return;
          }

          // Decode nonce from Base64
          // format of nonce is:
          //   base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
          String nonceAsPlainText = new String(Base64.decodeBase64(nonce.getBytes()));
          String[] nonceTokens = StringUtils.delimitedListToStringArray(nonceAsPlainText, ":");

          if (nonceTokens.length != 2) {
            fail(servletRequest, servletResponse,
                 new BadCredentialsException(messages.getMessage("DigestProcessingFilter.nonceNotTwoTokens",
                                                                 new Object[]{nonceAsPlainText}, "Nonce should have yielded two tokens but was {0}")));

            return;
          }

          // Extract expiry time from nonce
          long nonceExpiryTime;

          try {
            nonceExpiryTime = new Long(nonceTokens[0]).longValue();
          }
          catch (NumberFormatException nfe) {
            fail(servletRequest, servletResponse,
                 new BadCredentialsException(messages.getMessage("DigestProcessingFilter.nonceNotNumeric",
                                                                 new Object[]{nonceAsPlainText},
                                                                 "Nonce token should have yielded a numeric first token, but was {0}")));

            return;
          }

          // Check signature of nonce matches this expiry time
          String expectedNonceSignature = DigestUtils.md5Hex(nonceExpiryTime + ":"
            + this.getAuthenticationEntryPoint().getKey());

          if (!expectedNonceSignature.equals(nonceTokens[1])) {
            fail(servletRequest, servletResponse,
                 new BadCredentialsException(messages.getMessage("DigestProcessingFilter.nonceCompromised",
                                                                 new Object[]{nonceAsPlainText}, "Nonce token compromised {0}")));

            return;
          }

          // Lookup password for presented username
          // NB: DAO-provided password MUST be clear text - not encoded/salted
          // (unless this instance's passwordAlreadyEncoded property is 'false')
          boolean loadedFromDao = false;
          UserDetails user = userCache.getUserFromCache(username);

          if (user == null) {
            loadedFromDao = true;

            try {
              user = userDetailsService.loadUserByUsername(username);
            }
            catch (UsernameNotFoundException notFound) {
              fail(servletRequest, servletResponse,
                   new BadCredentialsException(messages.getMessage("DigestProcessingFilter.usernameNotFound",
                                                                   new Object[]{username}, "Username {0} not found")));

              return;
            }

            if (user == null) {
              throw new AuthenticationServiceException(
                "AuthenticationDao returned null, which is an interface contract violation");
            }

            userCache.putUserInCache(user);
          }

          // Compute the expected response-digest (will be in hex form)
          String serverDigestMd5;

          // Don't catch IllegalArgumentException (already checked validity)
          serverDigestMd5 = generateDigest(passwordAlreadyEncoded, username, realm, user.getPassword(),
                                           ((HttpServletRequest) servletRequest).getMethod(), uri, qop, nonce, nc, cnonce);

          // If digest is incorrect, try refreshing from backend and recomputing
          if (!serverDigestMd5.equals(responseDigest) && !loadedFromDao) {
            if (LOG.isDebugEnabled()) {
              LOG.debug(
                "Digest comparison failure; trying to refresh user from DAO in case password had changed");
            }

            try {
              user = userDetailsService.loadUserByUsername(username);
            }
            catch (UsernameNotFoundException notFound) {
              // Would very rarely happen, as user existed earlier
              fail(servletRequest, servletResponse,
                   new BadCredentialsException(messages.getMessage("DigestProcessingFilter.usernameNotFound",
                                                                   new Object[]{username}, "Username {0} not found")));
            }

            userCache.putUserInCache(user);

            // Don't catch IllegalArgumentException (already checked validity)
            serverDigestMd5 = generateDigest(passwordAlreadyEncoded, username, realm, user.getPassword(),
                                             ((HttpServletRequest) servletRequest).getMethod(), uri, qop, nonce, nc, cnonce);
          }

          // If digest is still incorrect, definitely reject authentication attempt
          if (!serverDigestMd5.equals(responseDigest)) {
            if (LOG.isDebugEnabled()) {
              LOG.debug("Expected response: '" + serverDigestMd5 + "' but received: '" + responseDigest
                + "'; is AuthenticationDao returning clear text passwords?");
            }

            fail(servletRequest, servletResponse,
                 new BadCredentialsException(messages.getMessage("DigestProcessingFilter.incorrectResponse",
                                                                 "Incorrect response")));

            return;
          }

          // To get this far, the digest must have been valid
          // Check the nonce has not expired
          // We do this last so we can direct the user agent its nonce is stale
          // but the request was otherwise appearing to be valid
          if (nonceExpiryTime < System.currentTimeMillis()) {
            fail(servletRequest, servletResponse,
                 new NonceExpiredException(messages.getMessage("DigestProcessingFilter.nonceExpired",
                                                               "Nonce has expired/timed out")));

            return;
          }

          if (LOG.isDebugEnabled()) {
            LOG.debug("Authentication success for user: '" + username + "' with response: '" + responseDigest
              + "'");
          }

          UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(user,
                                                                                                    user.getPassword());

          authRequest.setDetails(authenticationDetailsSource.buildDetails((HttpServletRequest) servletRequest));

          SecurityContextHolder.getContext().setAuthentication(authRequest);
        }
      }
      catch (AuthenticationException ae) {
        fail(request, response, ae);
      }
    }

    chain.doFilter(servletRequest, servletResponse);
  }


  private void fail(ServletRequest request, ServletResponse response, AuthenticationException failed) throws IOException, ServletException {
    SecurityContextHolder.getContext().setAuthentication(null);

    if (LOG.isDebugEnabled()) {
      LOG.debug(failed);
    }

    authenticationEntryPoint.commence(request, response, failed);
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
