package org.springframework.security.oauth.common.signature;

import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.x509.X509AuthenticationToken;
import static org.springframework.security.oauth.common.OAuthCodec.oauthEncode;

import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Implements the signatures defined in OAuth Core 1.0. By default, PLAINTEXT signatures are not supported
 *
 * @author Ryan Heaton
 */
public class CoreOAuthSignatureMethodFactory implements OAuthSignatureMethodFactory {

  private boolean supportPlainText = false;
  private boolean supportHMAC_SHA1 = true;
  private boolean supportRSA_SHA1 = true;

  public OAuthSignatureMethod getSignatureMethod(String methodName, SignatureSecret signatureSecret, String tokenSecret) throws UnsupportedSignatureMethodException {
    if (supportPlainText && PlainTextSignatureMethod.SIGNATURE_NAME.equals(methodName)) {
      if (!(signatureSecret instanceof SharedConsumerSecret)) {
        throw new IllegalArgumentException("Invalid secret for signature method " + methodName + ". Expected a " +
          SharedConsumerSecret.class.getName() + ", got " + (signatureSecret == null ? "null" : signatureSecret.getClass().getName()) + ".");
      }

      String consumerSecret = ((SharedConsumerSecret) signatureSecret).getConsumerSecret();
      if (consumerSecret == null) {
        consumerSecret = "";
      }
      if (tokenSecret == null) {
        tokenSecret = "";
      }

      consumerSecret = oauthEncode(consumerSecret);
      tokenSecret = oauthEncode(tokenSecret);
      
      return new PlainTextSignatureMethod(oauthEncode(new StringBuilder(consumerSecret).append('&').append(tokenSecret).toString()));
    }
    else if (supportHMAC_SHA1 && HMAC_SHA1SignatureMethod.SIGNATURE_NAME.equals(methodName)) {
      if (!(signatureSecret instanceof SharedConsumerSecret)) {
        throw new IllegalArgumentException("Invalid secret for signature method " + methodName + ". Expected a " +
          SharedConsumerSecret.class.getName() + ", got " + (signatureSecret == null ? "null" : signatureSecret.getClass().getName()) + ".");
      }

      String consumerSecret = ((SharedConsumerSecret) signatureSecret).getConsumerSecret();

      if (consumerSecret == null) {
        consumerSecret = "";
      }
      if (tokenSecret == null) {
        tokenSecret = "";
      }

      consumerSecret = oauthEncode(consumerSecret);
      tokenSecret = oauthEncode(tokenSecret);

      byte[] keyBytes;
      try {
        keyBytes = new StringBuilder(consumerSecret).append('&').append(tokenSecret).toString().getBytes("UTF-8");
      }
      catch (UnsupportedEncodingException e) {
        throw new RuntimeException(e.getMessage());
      }
      SecretKeySpec spec = new SecretKeySpec(keyBytes, HMAC_SHA1SignatureMethod.MAC_NAME);
      return new HMAC_SHA1SignatureMethod(spec);
    }
    else if (supportRSA_SHA1 && RSA_SHA1SignatureMethod.SIGNATURE_NAME.equals(methodName)) {
      if (signatureSecret instanceof RSAKeySecret) {
        PublicKey publicKey = ((RSAKeySecret) signatureSecret).getPublicKey();
        PrivateKey privateKey = ((RSAKeySecret) signatureSecret).getPrivateKey();
        return new RSA_SHA1SignatureMethod(privateKey, publicKey);
      }
      else {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if ((authentication.isAuthenticated()) && (authentication instanceof X509AuthenticationToken)) {
          X509Certificate certificate = (X509Certificate) ((X509AuthenticationToken) authentication).getCredentials();
          if (certificate != null) {
            return new RSA_SHA1SignatureMethod(certificate.getPublicKey());
          }
        }
      }
    }

    throw new UnsupportedSignatureMethodException("Unsupported signature method: " + methodName);    
  }

  /**
   * Whether to support the plain text signature method.
   *
   * @return Whether to support the plain text signature method.
   */
  public boolean isSupportPlainText() {
    return supportPlainText;
  }

  /**
   * Whether to support the plain text signature method.
   *
   * @param supportPlainText Whether to support the plain text signature method.
   */
  public void setSupportPlainText(boolean supportPlainText) {
    this.supportPlainText = supportPlainText;
  }

  /**
   * Whether to support HMAC-SHA1 signature method.
   *
   * @return Whether to support HMAC-SHA1 signature method.
   */
  public boolean isSupportHMAC_SHA1() {
    return supportHMAC_SHA1;
  }

  /**
   * Whether to support HMAC-SHA1 signature method.
   *
   * @param supportHMAC_SHA1 Whether to support HMAC-SHA1 signature method.
   */
  public void setSupportHMAC_SHA1(boolean supportHMAC_SHA1) {
    this.supportHMAC_SHA1 = supportHMAC_SHA1;
  }

  /**
   * Whether to support RSA-SHA1 signature method.
   *
   * @return Whether to support RSA-SHA1 signature method.
   */
  public boolean isSupportRSA_SHA1() {
    return supportRSA_SHA1;
  }

  /**
   * Whether to support RSA-SHA1 signature method.
   *
   * @param supportRSA_SHA1 Whether to support RSA-SHA1 signature method.
   */
  public void setSupportRSA_SHA1(boolean supportRSA_SHA1) {
    this.supportRSA_SHA1 = supportRSA_SHA1;
  }
}
