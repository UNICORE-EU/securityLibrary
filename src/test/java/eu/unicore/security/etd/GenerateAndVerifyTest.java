/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.helpers.BinaryCertChainValidator;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.security.ValidationResult;
import eu.unicore.security.etd.TrustDelegation;

/**
 * @author K. Benedyczak
 */
public class GenerateAndVerifyTest extends ETDTestBase
{
	public void testRSACert3()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerCert1[0], issuerCert1,
					privKey1, issuerCert3, null);
			
			String dnsubFromTD = new X500Principal(td.getSubjectDN()).getName();
			String dnsubOrig = issuerCert3[0].getSubjectX500Principal().getName();
			
			assertTrue(X500NameUtils.equal(dnsubFromTD, dnsubOrig));
			
			ValidationResult result = 
				etdEngine.validateTD(td, issuerCert1[0], issuerCert1, 
						issuerCert3, new BinaryCertChainValidator(true));
			if (!result.isValid())
				fail(result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	
	public void testRSACert2()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerCert3[0], issuerCert3,
					privKey4, receiverCert1, null);
			ValidationResult result = 
				etdEngine.validateTD(td, issuerCert3[0], issuerCert3, 
						receiverCert1, new BinaryCertChainValidator(true));
			if (!result.isValid())
				fail(result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	
	public void testRSACert()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerCert1[0], issuerCert1,
					privKey1, receiverCert1, null);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerCert1[0], issuerCert1, 
						receiverCert1, new BinaryCertChainValidator(true));
			if (!result.isValid())
				fail(result.getInvalidResaon());
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
			TrustDelegation td = etdEngine.generateTD(
					issuerCert2[0], issuerCert2, privKey2, receiverCert2, null);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerCert2[0], issuerCert2, receiverCert2, 
					new BinaryCertChainValidator(true));
			if (!result.isValid())
				fail(result.getInvalidResaon());		
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
			ValidationResult result = 
				etdEngine.validateTD(td, issuerDN1, issuerDN1, receiverDN1, 
					new BinaryCertChainValidator(true));
			if (!result.isValid())
				fail(result.getInvalidResaon());		
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
			TrustDelegation td = etdEngine.generateTD(
					issuerDN2, issuerCert2, privKey2, receiverDN2, null);
			ValidationResult result = 
				etdEngine.validateTD(td, issuerDN2, issuerDN2, receiverDN2, 
					new BinaryCertChainValidator(true));
			if (!result.isValid())
				fail(result.getInvalidResaon());		
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}
}
