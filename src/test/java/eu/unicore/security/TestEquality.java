package eu.unicore.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;

/**
 * @author K. Benedyczak
 */
public class TestEquality
{
	
	@Test
	public void test() throws Exception {
		MockSecurityConfig cfg = new MockSecurityConfig(false, true, true);
		MockSecurityConfig cfgWrong = new MockSecurityConfig(false, true, false);

		X509Certificate cp1[] = new X509Certificate[] {cfg.getCredential().getCertificate()};

		X509Certificate[] cp2 = new X509Certificate[] {cfgWrong.getCredential().getCertificate()};

		SecurityTokens t1 = new SecurityTokens();
		SecurityTokens t2 = new SecurityTokens();
		assertTrue(t1.equals(t2));

		t1.setConsignor(cp1);
		assertFalse(t1.equals(t2));			
		t2.setConsignor(cp1);
		assertTrue(t1.equals(t2));

		t1.setConsignorTrusted(true);
		assertFalse(t1.equals(t2));			
		t2.setConsignorTrusted(true);
		assertTrue(t1.equals(t2));

		t1.setUser(cp2);
		assertFalse(t1.equals(t2));			
		t2.setUser(cp2);
		assertTrue(t1.equals(t2));
	}
}
