package org.springframework.security.oauth.provider;

import org.acegisecurity.util.StringSplitUtils;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import static org.springframework.security.oauth.common.OAuthCodec.*;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.*;

/**
 * Utility for common logic for supporting an OAuth provider.
 *
 * @author Ryan Heaton
 */
public class CoreOAuthProviderSupport implements OAuthProviderSupport {

  private final Set<String> supportedOAuthParameters;
  private String baseUrl = null;

  public CoreOAuthProviderSupport() {
    Set<String> supportedOAuthParameters = new HashSet<String>();
    for (OAuthConsumerParameter supportedParameter : OAuthConsumerParameter.values()) {
      supportedOAuthParameters.add(supportedParameter.toString());
    }
    this.supportedOAuthParameters = Collections.unmodifiableSet(supportedOAuthParameters);
  }

  // Inherited.
  public Map<String, String> parseParameters(HttpServletRequest request) {
    Map<String, String> parameters = new HashMap<String, String>();

    String header = request.getHeader("Authorization");
    if ((header != null) && (header.toLowerCase().startsWith("oauth "))) {
      String authHeaderValue = header.substring(6);

      //create a map of the authorization header values per OAuth Core 1.0, section 5.4.1
      String[] headerEntries = StringSplitUtils.splitIgnoringQuotes(authHeaderValue, ',');
      Iterator headerEntriesIt = StringSplitUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"").entrySet().iterator();
      while (headerEntriesIt.hasNext()) {
        Map.Entry entry = (Map.Entry) headerEntriesIt.next();
        String key = (String) entry.getKey();
        String value = (String) entry.getValue();
        try {
          //attempt to URL decode the key-value pairs.
          key = URLDecoder.decode(key, "utf-8");
          value = URLDecoder.decode(value, "utf-8");
        }
        catch (UnsupportedEncodingException e) {
          //fall through...
        }

        parameters.put(key, value);
      }
    }
    else {
      Set<String> supportedOAuthParameters = getSupportedOAuthParameters();
      for (String supportedOAuthParameter : supportedOAuthParameters) {
        parameters.put(supportedOAuthParameter, request.getParameter(supportedOAuthParameter));
      }
    }

    return parameters;
  }

  /**
   * Get the supported OAuth parameters. The default implementation supports only the OAuth core parameters.
   *
   * @return The OAuth core parameters.
   */
  protected Set<String> getSupportedOAuthParameters() {
    return this.supportedOAuthParameters;
  }

  // Inherited.
  public String getSignatureBaseString(HttpServletRequest request) {
    Map<String, String> significantParameters = loadSignificantParametersForSignatureBaseString(request);

    //now sort them (according to the spec.
    Map.Entry<String, String>[] sortedParameters = significantParameters.entrySet().toArray(new Map.Entry[significantParameters.size()]);
    Comparator<Map.Entry<String, String>> parameterComparator = new Comparator<Map.Entry<String, String>>() {
      public int compare(Map.Entry<String, String> param1, Map.Entry<String, String> param2) {
        int comparison = param1.getKey().compareTo(param2.getKey());
        if (comparison == 0) {
          comparison = param1.getValue().compareTo(param2.getValue());
        }
        return comparison;
      }
    };
    Arrays.sort(sortedParameters, parameterComparator);

    //now concatenate them into a single query string according to the spec.
    StringBuilder queryString = new StringBuilder();
    for (int i = 0; i < sortedParameters.length; i++) {
      Map.Entry<String, String> sortedParameter = sortedParameters[i];
      queryString.append(sortedParameter.getKey()).append('=').append(sortedParameter.getValue());
      if (i + 1 < sortedParameters.length) {
        queryString.append('&');
      }
    }

    String url = getBaseUrl();
    if (url == null) {
      //if no URL is configured, then we'll attempt to reconstruct the URL.  This may be inaccurate.
      url = request.getRequestURL().toString();
    }
    url = oauthEncode(url);

    String method = request.getMethod().toUpperCase();
    return new StringBuilder(method).append('&').append(url).append('&').append(oauthEncode(queryString.toString())).toString();
  }

  /**
   * Loads the significant parameters (name-to-value map) that are to be used to calculate the signature base string.
   *
   * @param request The request.
   * @return The significan parameters.
   */
  protected Map<String, String> loadSignificantParametersForSignatureBaseString(HttpServletRequest request) {
    //first collect the relevant parameters...
    Map<String, String> significantParameters = new HashMap<String, String>();
    //first pull from the request...
    Enumeration parameterNames = request.getParameterNames();
    while (parameterNames.hasMoreElements()) {
      String parameterName = (String) parameterNames.nextElement();
      String parameterValue = request.getParameter(parameterName);
      if (parameterValue == null) {
        parameterValue = "";
      }

      parameterName = oauthEncode(parameterName);
      parameterValue = oauthEncode(parameterValue);

      significantParameters.put(parameterName, parameterValue);
    }

    //then take into account the header parameter values...
    Map<String, String> oauthParams = parseParameters(request);
    oauthParams.remove("realm"); //remove the realm
    Set<String> parsedParams = oauthParams.keySet();
    for (String parameterName : parsedParams) {
      String parameterValue = oauthParams.get(parameterName);
      if (parameterValue == null) {
        parameterValue = "";
      }

      parameterName = oauthEncode(parameterName);
      parameterValue = oauthEncode(parameterValue);

      significantParameters.put(parameterName, parameterValue);
    }

    //remove the oauth signature parameter value.
    significantParameters.remove(OAuthConsumerParameter.oauth_signature.toString());
    return significantParameters;
  }

  /**
   * The configured base URL for this OAuth provider.
   *
   * @return The configured base URL for this OAuth provider.
   */
  public String getBaseUrl() {
    return baseUrl;
  }

  /**
   * The configured base URL for the OAuth provider.
   *
   * @param baseUrl The configured base URL for the OAuth provider.
   */
  public void setBaseUrl(String baseUrl) {
    this.baseUrl = baseUrl;
  }
}
