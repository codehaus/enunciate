package org.springframework.security.oauth.common.signature;

import junit.framework.TestCase;

import javax.crypto.spec.SecretKeySpec;

/**
 * @author Ryan Heaton
 */
public class TestHMAC_SHA1SignatureMethod extends TestCase {

  /**
   * Test sign and verify.
   */
  public void testSignAndVerify() throws Exception {
    SecretKeySpec spec = new SecretKeySpec("thisismysharedsecretkeythatidontwanttoshare".getBytes("UTF-8"), HMAC_SHA1SignatureMethod.MAC_NAME);
    HMAC_SHA1SignatureMethod signatureMethod = new HMAC_SHA1SignatureMethod(spec);
    String baseString = "thisismysignaturebasestringthatshouldbemuchlongerthanthisbutitdoesnthavetobeandherearesomestrangecharacters!@#$%^&*)(*";
    String signature = signatureMethod.sign(baseString);
    signatureMethod.verify(baseString, signature);
  }

}
