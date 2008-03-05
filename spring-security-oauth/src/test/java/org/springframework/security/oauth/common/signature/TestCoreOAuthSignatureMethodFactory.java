package org.springframework.security.oauth.common.signature;

import junit.framework.TestCase;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenImpl;

import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.security.KeyPairGenerator;
import java.security.KeyPair;

/**
 * @author Ryan Heaton
 */
public class TestCoreOAuthSignatureMethodFactory extends TestCase {

  /**
   * tests getting the signature method.
   */
  public void testGetSignatureMethod() throws Exception {
    CoreOAuthSignatureMethodFactory factory = new CoreOAuthSignatureMethodFactory();
    OAuthProviderTokenImpl token = new OAuthProviderTokenImpl();
    token.setSecret("token_SHHHHHHHHHHHHHH");
    SharedConsumerSecret sharedSecret = new SharedConsumerSecret("consumer_shhhhhhhhhh");
    try {
      factory.getSignatureMethod("unknown", sharedSecret, token.getSecret());
      fail("should fail with unknown signature method.");
    }
    catch (UnsupportedSignatureMethodException e) {
      //fall thru...
    }

    try {
      factory.getSignatureMethod(PlainTextSignatureMethod.SIGNATURE_NAME, sharedSecret, token.getSecret());
      fail("plain text shouldn't be supported by default.");
    }
    catch (UnsupportedSignatureMethodException e) {
      //fall thru...
    }

    factory.setSupportPlainText(true);
    OAuthSignatureMethod signatureMethod = factory.getSignatureMethod(PlainTextSignatureMethod.SIGNATURE_NAME, sharedSecret, token.getSecret());
    assertTrue(signatureMethod instanceof PlainTextSignatureMethod);
    assertEquals("consumer_shhhhhhhhhh%26token_SHHHHHHHHHHHHHH", ((PlainTextSignatureMethod) signatureMethod).getSecret());

    signatureMethod = factory.getSignatureMethod(HMAC_SHA1SignatureMethod.SIGNATURE_NAME, sharedSecret, token.getSecret());
    assertTrue(signatureMethod instanceof HMAC_SHA1SignatureMethod);
    SecretKeySpec spec = new SecretKeySpec("consumer_shhhhhhhhhh&token_SHHHHHHHHHHHHHH".getBytes("UTF-8"), HMAC_SHA1SignatureMethod.MAC_NAME);
    assertTrue(Arrays.equals(spec.getEncoded(), ((HMAC_SHA1SignatureMethod) signatureMethod).getSecretKey().getEncoded()));

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(1024);
    KeyPair keyPair = generator.generateKeyPair();
    signatureMethod = factory.getSignatureMethod(RSA_SHA1SignatureMethod.SIGNATURE_NAME, new RSAKeySecret(keyPair.getPrivate(), keyPair.getPublic()), token.getSecret());
    assertTrue(signatureMethod instanceof RSA_SHA1SignatureMethod);
    assertEquals(keyPair.getPrivate(), ((RSA_SHA1SignatureMethod) signatureMethod).getPrivateKey());
    assertEquals(keyPair.getPublic(), ((RSA_SHA1SignatureMethod) signatureMethod).getPublicKey());
  }

}
