/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

import java.math.BigInteger;
import java.util.Date;

import org.apache.xmlbeans.XmlObject;

import eu.unicore.security.ValidationResult;
import eu.unicore.security.etd.TrustDelegation;
import xmlbeans.org.oasis.saml2.assertion.ConditionAbstractType;
import xmlbeans.org.oasis.saml2.assertion.ProxyRestrictionDocument;
import xmlbeans.org.oasis.saml2.assertion.ProxyRestrictionType;

/**
 * @author K. Benedyczak
 */
public class ParseTest extends ETDTestBase
{
	public void testDN()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerDN3, issuerCert3,
					privKey4, receiverDN1, null);

			TrustDelegation td2 = new TrustDelegation(td.getXML());
			System.out.println("-------------------------------------------\n" + 
				"TD with RSA key, DN:");
				System.out.println(td.getXML().xmlText(xmlOpts));
			System.out.println("-------------------------------------------\n" + 
				"TD parsed with RSA key, DN:");
			System.out.println(td2.getXML().xmlText(xmlOpts));
			
			ValidationResult result = 
				etdEngine.validateTD(td2, issuerDN3, issuerDN3, receiverDN1);
			if (!result.isValid())
				fail(result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	public void testCert()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerCert1[0], issuerCert1,
					privKey1, receiverCert1, null);

			TrustDelegation td2 = new TrustDelegation(td.getXML());
			System.out.println("-------------------------------------------\n" + 
				"TD with RSA key, Cert:");
				System.out.println(td.getXML().xmlText(xmlOpts));
			System.out.println("-------------------------------------------\n" + 
				"TD parsed with RSA key, Cert:");
			System.out.println(td2.getXML().xmlText(xmlOpts));
			
			ValidationResult result = 
				etdEngine.validateTD(td2, issuerCert1[0], issuerCert1, 
						receiverCert1);
			if (!result.isValid())
				fail(result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}
	
	public void testCustomRestriction()
	{
		try
		{
			DelegationRestrictions rest = new DelegationRestrictions(new Date(), 1, 1);
			
			ProxyRestrictionDocument restDoc = ProxyRestrictionDocument.Factory.newInstance();
			ProxyRestrictionType customRest = restDoc.addNewProxyRestriction();
			customRest.setCount(BigInteger.TEN);
			rest.setCustomConditions(new XmlObject[] {restDoc});
			
			TrustDelegation td = etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, receiverDN1, rest);

			TrustDelegation td2 = new TrustDelegation(td.getXML());

			System.out.println("-------------------------------------------\n" + 
				"TD parsed with custom restriction:");
			System.out.println(td2.getXML().xmlText(xmlOpts));
			
			ValidationResult result = 
				etdEngine.validateTD(td2, issuerDN1, issuerDN1, receiverDN1);
			if (!result.isValid())
				fail(result.getInvalidResaon());
			
			ConditionAbstractType []customC = td2.getCustomConditions();
			if (customC == null || customC.length != 1)
				fail("No custom conditions after parsing");
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}
}

