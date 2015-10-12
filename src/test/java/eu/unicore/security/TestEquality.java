/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 31, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.cert.X509Certificate;

import org.junit.Test;

/**
 * @author K. Benedyczak
 */
public class TestEquality
{
	
	@Test
	public void test()
	{
		try
		{
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
			
			t1.setMessageSignatureStatus(SignatureStatus.OK);
			assertFalse(t1.equals(t2));			
			t2.setMessageSignatureStatus(SignatureStatus.OK);
			assertTrue(t1.equals(t2));
			
			t1.setUser(cp2);
			assertFalse(t1.equals(t2));			
			t2.setUser(cp2);
			assertTrue(t1.equals(t2));
		} catch(Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		
	}
}
