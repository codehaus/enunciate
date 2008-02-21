package org.springframework.security.oauth.provider;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.util.StringSplitUtils;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.acegisecurity.ui.AuthenticationDetailsSource;
import org.acegisecurity.ui.AuthenticationDetailsSourceImpl;
import org.acegisecurity.ui.AuthenticationEntryPoint;
import org.acegisecurity.ui.rememberme.RememberMeServices;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
import java.net.URLDecoder;

/**
 * Processing filter for OAuth authentication requests.  Initial code was lifted from
 * {@link org.acegisecurity.ui.basicauth.BasicProcessingFilter}
 *
 * @author Ryan Heaton
 */
public class OAuthProcessingFilter implements Filter, InitializingBean {

  private static final Log LOG = LogFactory.getLog(OAuthProcessingFilter.class);

  private AuthenticationDetailsSource authenticationDetailsSource = new AuthenticationDetailsSourceImpl();
  private AuthenticationManager authenticationManager;
  private AuthenticationEntryPoint authenticationEntryPoint;
  private RememberMeServices rememberMeServices;
  private boolean ignoreFailure = true;

  // Inherited.
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.authenticationManager, "An AuthenticationManager is required");
    if (!ignoreFailure) {
      Assert.notNull(this.authenticationEntryPoint, "An AuthenticationEntryPoint is required");
    }
  }

  // Inherited.
  public void destroy() {
    //no-op
  }

  /**
   * Filter the request through OAuth authentication processing.
   *
   * @param servletRequest The request.
   * @param servletResponse The response.
   * @param chain The filter chain.
   */
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    String header = request.getHeader("Authorization");
    if ((header != null) && (header.toLowerCase().startsWith("oauth "))) {
      String authHeaderValue = header.substring(6);

      //create a map of the authorization header values per OAuth Core 1.0, section 5.4.1
      String[] headerEntries = StringSplitUtils.splitIgnoringQuotes(authHeaderValue, ',');
      Map<String, String> headerMap = new HashMap<String, String>();
      Iterator headerEntriesIt = StringSplitUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"").entrySet().iterator();
      while (headerEntriesIt.hasNext()) {
        Map.Entry entry = (Map.Entry) headerEntriesIt.next();
        String key = URLDecoder.decode((String) entry.getKey(), "utf-8");
        String value = URLDecoder.decode((String) entry.getValue(), "utf-8");
        headerMap.put(key, value);
      }

      String consumerKey = headerMap.remove("oauth_consumer_key");
      String signatureMethod = headerMap.remove("oauth_signature_method");
      String signature = headerMap.remove("oauth_signature");
      String timestamp = headerMap.remove("oauth_timestamp");
      String nonce = headerMap.remove("oauth_nonce");
      String version = headerMap.remove("oauth_version");

      if ((version != null) && (!"1.0".equals(version))) {
        throw new OAuthVersionUnsupportedException("Unsupported OAuth version: " + version);
      }

      String username = "";
      String password = "";
      int delim = token.indexOf(":");

      if (delim != -1) {
        username = token.substring(0, delim);
        password = token.substring(delim + 1);
      }

      if (authenticationIsRequired(username)) {
        UsernamePasswordAuthenticationToken authRequest =
          new UsernamePasswordAuthenticationToken(username, password);
        authRequest.setDetails(authenticationDetailsSource.buildDetails((HttpServletRequest) servletRequest));

        Authentication authResult;

        try {
          authResult = authenticationManager.authenticate(authRequest);
        }
        catch (AuthenticationException failed) {
          // Authentication failed
          if (LOG.isDebugEnabled()) {
            LOG.debug("Authentication request for user: " + username + " failed: " + failed.toString());
          }

          SecurityContextHolder.getContext().setAuthentication(null);

          if (rememberMeServices != null) {
            rememberMeServices.loginFail(request, response);
          }

          if (ignoreFailure) {
            chain.doFilter(servletRequest, servletResponse);
          }
          else {
            authenticationEntryPoint.commence(servletRequest, servletResponse, failed);
          }

          return;
        }

        // Authentication success
        if (LOG.isDebugEnabled()) {
          LOG.debug("Authentication success: " + authResult.toString());
        }

        SecurityContextHolder.getContext().setAuthentication(authResult);

        if (rememberMeServices != null) {
          rememberMeServices.loginSuccess(request, response, authResult);
        }
      }
    }

    chain.doFilter(servletRequest, servletResponse);
  }

  private boolean authenticationIsRequired(String username) {
    // Only reauthenticate if username doesn't match SecurityContextHolder and user isn't authenticated
    // (see SEC-53)
    Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();

    if (existingAuth == null || !existingAuth.isAuthenticated()) {
      return true;
    }

    // Limit username comparison to providers which use usernames (ie UsernamePasswordAuthenticationToken)
    // (see SEC-348)

    if (existingAuth instanceof UsernamePasswordAuthenticationToken && !existingAuth.getName().equals(username)) {
      return true;
    }

    // Handle unusual condition where an AnonymousAuthenticationToken is already present
    // This shouldn't happen very often, as BasicProcessingFitler is meant to be earlier in the filter
    // chain than AnonymousProcessingFilter. Nevertheless, presence of both an AnonymousAuthenticationToken
    // together with a BASIC authentication request header should indicate reauthentication using the
    // BASIC protocol is desirable. This behaviour is also consistent with that provided by form and digest,
    // both of which force re-authentication if the respective header is detected (and in doing so replace
    // any existing AnonymousAuthenticationToken). See SEC-610.
    if (existingAuth instanceof AnonymousAuthenticationToken) {
      return true;
    }

    return false;
  }

  public AuthenticationEntryPoint getAuthenticationEntryPoint() {
    return authenticationEntryPoint;
  }

  public AuthenticationManager getAuthenticationManager() {
    return authenticationManager;
  }

  public void init(FilterConfig arg0) throws ServletException {
  }

  public boolean isIgnoreFailure() {
    return ignoreFailure;
  }

  public void setAuthenticationDetailsSource(AuthenticationDetailsSource authenticationDetailsSource) {
    Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
    this.authenticationDetailsSource = authenticationDetailsSource;
  }

  public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
    this.authenticationEntryPoint = authenticationEntryPoint;
  }

  public void setAuthenticationManager(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

  public void setIgnoreFailure(boolean ignoreFailure) {
    this.ignoreFailure = ignoreFailure;
  }

  public void setRememberMeServices(RememberMeServices rememberMeServices) {
    this.rememberMeServices = rememberMeServices;
  }

}
