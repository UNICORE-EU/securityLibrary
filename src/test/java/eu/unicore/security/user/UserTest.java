/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.user;

import eu.unicore.security.TestBase;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;

/**
 * @author K. Benedyczak
 */
public class UserTest extends TestBase
{
	public void testUserAsDN()
	{
		try
		{
			UserAssertion token = new UserAssertion(issuerDN1, issuerDN2);
			System.out.println("-------------------------------------------\n" + 
				"User token:");
			System.out.println(token.getXML().xmlText(xmlOpts));
			
			AssertionDocument doc = token.getXML();
			UserAssertion parsedToken = new UserAssertion(doc);
			System.out.println("-------------------------------------------\n" + 
				"Parsed user token:");
			System.out.println(parsedToken.getXML().xmlText(xmlOpts));

		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	public void testUserAsCert()
	{
		try
		{
			UserAssertion token = new UserAssertion(issuerDN1, issuerCert2);
			System.out.println("-------------------------------------------\n" + 
				"User token:");
			System.out.println(token.getXML().xmlText(xmlOpts));
			
			AssertionDocument doc = token.getXML();
			UserAssertion parsedToken = new UserAssertion(doc);
			
			System.out.println("-------------------------------------------\n" + 
				"Parsed user token:");
			System.out.println(parsedToken.getXML().xmlText(xmlOpts));
			System.out.println("User's certificate parsed: " + 
					parsedToken.getUserCertificate());

		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}

}
