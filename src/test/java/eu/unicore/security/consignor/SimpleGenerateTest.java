/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.consignor;

import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.SAMLConstants.AuthNClasses;
import eu.unicore.security.TestBase;
import eu.unicore.security.UnicoreSecurityFactory;
import eu.unicore.security.ValidationResult;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;

/**
 * @author K. Benedyczak
 */
public class SimpleGenerateTest extends TestBase
{
	public void test1()
	{
		try
		{
			ConsignorAPI impl = UnicoreSecurityFactory.getConsignorAPI();
			ConsignorAssertion token = 
				impl.generateConsignorToken(issuerDN2, issuerCert1, privKey2,
						0, 5, AuthNClasses.TLS, "127.0.0.1");
			
			System.out.println("-------------------------------------------\n" + 
					"Consignor token:");
			System.out.println(token.getXMLBeanDoc().xmlText(xmlOpts));
			
			AssertionDocument doc = token.getXMLBeanDoc();
			ConsignorAssertion parsedToken = new ConsignorAssertion(doc);
			if (!parsedToken.isSigned())
				fail("Assertion doesn't report itself as signed");
			ValidationResult res = 
				impl.verifyConsignorToken(parsedToken, issuerCert2[0]);
			if (!res.isValid())
				fail(res.getInvalidResaon());
			assertEquals("127.0.0.1", parsedToken.getXMLBean().getAuthnStatementArray(0).getSubjectLocality().getAddress());
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}
	
	public void test2()
	{
		try
		{
			ConsignorAPI impl = UnicoreSecurityFactory.getConsignorAPI();
			X500Principal c1 = issuerCert1[0].getSubjectX500Principal();
			ConsignorAssertion token = 
				impl.generateConsignorToken(issuerDN2, issuerCert1,
						AuthNClasses.TLS, "127.0.0.1");
			
			System.out.println("-------------------------------------------\n" + 
					"Consignor token:");
			System.out.println(token.getXMLBeanDoc().xmlText(xmlOpts));
			
			AssertionDocument doc = token.getXMLBeanDoc();
			ConsignorAssertion parsedToken = new ConsignorAssertion(doc);
			if (parsedToken.isSigned())
				fail("Assertion maliciously report itself as signed");
			ValidationResult res = 
				impl.verifyConsignorToken(parsedToken, issuerCert2[0]);
			if (!res.isValid())
				fail(res.getInvalidResaon());
			X509Certificate []cert = parsedToken.getConsignor();
			X500Principal c2 = cert[0].getSubjectX500Principal();
			System.out.println("Consignor read back is: " + c2);
			if (!X500NameUtils.rfc3280Equal(c1, c2))
				fail("Consignor is not the same after parsing");
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}
	
	public void testExpiredCert1()
	{
		try
		{
			ConsignorAPI impl = UnicoreSecurityFactory.getConsignorAPI();
			ConsignorAssertion token = 
				impl.generateConsignorToken(issuerDN2, expiredCert,
						AuthNClasses.TLS, "127.0.0.1");
			
			AssertionDocument doc = token.getXMLBeanDoc();
			ConsignorAssertion parsedToken = new ConsignorAssertion(doc);
			ValidationResult res = 
				impl.verifyConsignorToken(parsedToken, expiredCert[0]);
			if (res.isValid())
				fail("Assertion issued with expired cert was accepted");
			
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}
}
