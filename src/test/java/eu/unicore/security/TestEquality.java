/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 31, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security;

import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;

import junit.framework.TestCase;
import eu.unicore.security.SecurityTokens;
import eu.unicore.security.SignatureStatus;

/**
 * @author K. Benedyczak
 */
public class TestEquality extends TestCase
{
	public void test()
	{
		try
		{
			MockSecurityConfig cfg = new MockSecurityConfig(false, false, true);
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			
			ArrayList<Certificate> certs1 = new ArrayList<Certificate>();
			certs1.add(cfg.getUserCert(MockSecurityConfig.KS_ALIAS));
			CertPath cp1 = factory.generateCertPath(certs1);

			ArrayList<Certificate> certs2 = new ArrayList<Certificate>();
			certs2.add(cfg.getUserCert(MockSecurityConfig.KS_ALIAS_WRONG));
			CertPath cp2 = factory.generateCertPath(certs2);

			SecurityTokens t1 = new SecurityTokens();
			SecurityTokens t2 = new SecurityTokens();
			assertTrue(t1.equals(t2));

			t1.setConsignor(cp1);
			assertFalse(t1.equals(t2));			
			t2.setConsignor(cp1);
			assertTrue(t1.equals(t2));
			
			t1.setValidTrustDelegation(true);
			assertFalse(t1.equals(t2));			
			t2.setValidTrustDelegation(true);
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
