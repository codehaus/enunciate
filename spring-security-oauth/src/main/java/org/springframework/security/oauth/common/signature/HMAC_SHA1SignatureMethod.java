package org.springframework.security.oauth.common.signature;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import static org.springframework.security.oauth.common.OAuthCodec.oauthDecode;
import static org.springframework.security.oauth.common.OAuthCodec.oauthEncode;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * HMAC-SHA1 signature method.
 *
 * @author Ryan Heaton
 */
public class HMAC_SHA1SignatureMethod implements OAuthSignatureMethod {

  /**
   * The name of this HMAC-SHA1 signature method ("HMAC-SHA1").
   */
  public static final String SIGNATURE_NAME = "HMAC-SHA1";

  /**
   * The MAC name (for interfacing with javax.crypto.*).  "HmacSHA1".
   */
  public static final String MAC_NAME = "HmacSHA1";

  private final SecretKey key;

  /**
   * Construct a HMAC-SHA1 signature method with the given HMAC-SHA1 key.
   *
   * @param key The key.
   */
  public HMAC_SHA1SignatureMethod(SecretKey key) {
    this.key = key;
  }

  /**
   * The name of this HMAC-SHA1 signature method ("HMAC-SHA1").
   *
   * @return The name of this HMAC-SHA1 signature method.
   */
  public String getName() {
    return SIGNATURE_NAME;
  }

  /**
   * Sign the signature base string. The signature is the digest octet string, first base64-encoded per RFC2045, section 6.8, then URL-encoded per
   * OAuth Parameter Encoding.
   *
   * @param signatureBaseString The signature base string.
   * @return The signature.
   */
  public String sign(String signatureBaseString) {
    try {
      Mac mac = Mac.getInstance(MAC_NAME);
      mac.init(key);
      byte[] text = signatureBaseString.getBytes("UTF-8");
      byte[] signatureBytes = mac.doFinal(text);
      signatureBytes = Base64.encodeBase64(signatureBytes);
      String signature = new String(signatureBytes, "UTF-8");
      return oauthEncode(signature);
    }
    catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    catch (InvalidKeyException e) {
      throw new IllegalStateException(e);
    }
    catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Verify the signature of the given signature base string. The signature is verified by generating a new request signature octet string, and comparing it
   * to the signature provided by the Consumer, first URL-decoded per Parameter Encoding, then base64-decoded per RFC2045 section 6.8. The signature is
   * generated using the request parameters as provided by the Consumer, and the Consumer Secret and Token Secret as stored by the Service Provider.
   * 
   * @param signatureBaseString The signature base string.
   * @param signature The signature.
   * @throws InvalidSignatureException If the signature is invalid for the specified base string.
   */
  public void verify(String signatureBaseString, String signature) throws InvalidSignatureException {
    try {
      signature = oauthDecode(signature);
      byte[] signatureBytes = Base64.decodeBase64(signature.getBytes("UTF-8"));

      Mac mac = Mac.getInstance(MAC_NAME);
      mac.init(key);
      byte[] text = signatureBaseString.getBytes("UTF-8");
      byte[] calculatedBytes = mac.doFinal(text);
      if (!Arrays.equals(calculatedBytes, signatureBytes)) {
        throw new InvalidSignatureException("Invalid signature for signature method " + getName());
      }
    }
    catch (DecoderException e) {
      throw new InvalidSignatureException("Unable to decode signature.", e);
    }
    catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    catch (InvalidKeyException e) {
      throw new IllegalStateException(e);
    }
    catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * The secret key.
   *
   * @return The secret key.
   */
  public SecretKey getSecretKey() {
    return key;
  }
}