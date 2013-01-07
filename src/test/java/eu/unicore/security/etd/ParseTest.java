/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

import eu.emi.security.authn.x509.helpers.BinaryCertChainValidator;
import eu.unicore.security.ValidationResult;
import eu.unicore.security.etd.TrustDelegation;

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

			TrustDelegation td2 = new TrustDelegation(td.getXMLBeanDoc());
			System.out.println("-------------------------------------------\n" + 
				"TD with RSA key, DN:");
				System.out.println(td.getXMLBeanDoc().xmlText(xmlOpts));
			System.out.println("-------------------------------------------\n" + 
				"TD parsed with RSA key, DN:");
			System.out.println(td2.getXMLBeanDoc().xmlText(xmlOpts));
			
			ValidationResult result = 
				etdEngine.validateTD(td2, issuerDN3, issuerDN3, receiverDN1, new BinaryCertChainValidator(true));
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

			TrustDelegation td2 = new TrustDelegation(td.getXMLBeanDoc());
			System.out.println("-------------------------------------------\n" + 
				"TD with RSA key, Cert:");
				System.out.println(td.getXMLBeanDoc().xmlText(xmlOpts));
			System.out.println("-------------------------------------------\n" + 
				"TD parsed with RSA key, Cert:");
			System.out.println(td2.getXMLBeanDoc().xmlText(xmlOpts));
			
			ValidationResult result = 
				etdEngine.validateTD(td2, issuerCert1[0], issuerCert1, 
						receiverCert1, new BinaryCertChainValidator(true));
			if (!result.isValid())
				fail(result.getInvalidResaon());
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}
}

