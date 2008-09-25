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

import eu.unicore.saml.SAMLConstants.AuthNClasses;
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
						0, 5, AuthNClasses.TLS);
			
			System.out.println("-------------------------------------------\n" + 
					"Consignor token:");
			System.out.println(token.getXML().xmlText(xmlOpts));
			
			AssertionDocument doc = token.getXML();
			ConsignorAssertion parsedToken = new ConsignorAssertion(doc);
			if (!parsedToken.isSigned())
				fail("Assertion doesn't report itself as signed");
			ValidationResult res = 
				impl.verifyConsignorToken(parsedToken, issuerCert2[0]);
			if (!res.isValid())
				fail(res.getInvalidResaon());
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
			String c1 = issuerCert1[0].getSubjectX500Principal().getName(X500Principal.CANONICAL);
			ConsignorAssertion token = 
				impl.generateConsignorToken(issuerDN2, issuerCert1,
						AuthNClasses.TLS);
			
			System.out.println("-------------------------------------------\n" + 
					"Consignor token:");
			System.out.println(token.getXML().xmlText(xmlOpts));
			
			AssertionDocument doc = token.getXML();
			ConsignorAssertion parsedToken = new ConsignorAssertion(doc);
			if (parsedToken.isSigned())
				fail("Assertion maliciously report itself as signed");
			ValidationResult res = 
				impl.verifyConsignorToken(parsedToken, issuerCert2[0]);
			if (!res.isValid())
				fail(res.getInvalidResaon());
			X509Certificate []cert = parsedToken.getConsignor();
			String c2 = cert[0].getSubjectX500Principal().getName(X500Principal.CANONICAL);
			System.out.println("Consignor read back is: " + c2);
			if (!c1.equals(c2))
				fail("Consignor is not the same after parsing");
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}
}
