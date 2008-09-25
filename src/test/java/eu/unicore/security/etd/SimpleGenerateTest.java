/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

import eu.unicore.security.etd.TrustDelegation;

/**
 * @author K. Benedyczak
 */
public class SimpleGenerateTest extends ETDTestBase
{
	public void testRSACert()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerCert1[0], issuerCert1,
					privKey1, receiverCert1, null);
			System.out.println("-------------------------------------------\n" + 
					"TD with RSA key, and cert boundled:");
			System.out.println(td.getXML().xmlText(xmlOpts));
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	public void testDSACert()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerCert2[0], issuerCert2,
					privKey2, receiverCert2, null);
			System.out.println("\n-------------------------------------------\n" + 
				"TD with DSA key, and cert boundled:");
			System.out.println(td.getXML().xmlText(xmlOpts));
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	public void testRSADN()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, receiverDN1, null);
			System.out.println("\n-------------------------------------------\n" + 
				"TD with RSA key, without cert boundled:");
			System.out.println(td.getXML().xmlText(xmlOpts));
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	public void testDSADN()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerDN2, issuerCert2,
					privKey2, receiverDN2, null);
			System.out.println("\n-------------------------------------------\n" + 
				"TD with DSA key, without cert:");
			System.out.println(td.getXML().xmlText(xmlOpts));
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}
}
