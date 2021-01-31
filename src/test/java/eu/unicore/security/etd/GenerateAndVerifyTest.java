/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

import static org.junit.Assert.*;

import java.util.Collections;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;

import eu.emi.security.authn.x509.helpers.BinaryCertChainValidator;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.security.ValidationResult;

public class GenerateAndVerifyTest extends ETDTestBase
{
	@Test
	public void testWithCustomAttributes()
	{
		try
		{
			SAMLAttribute samlA = new SAMLAttribute("foo", "bar");
			samlA.addStringAttributeValue("bar");
			
			TrustDelegation td = etdEngine.generateTD(issuerCert1[0], issuerCert1,
					privKey1, issuerCert3, null, Collections.singletonList(samlA));
			
			String dnsubFromTD = new X500Principal(td.getSubjectName()).getName();
			String dnsubOrig = issuerCert3[0].getSubjectX500Principal().getName();
			
			assertTrue(X500NameUtils.equal(dnsubFromTD, dnsubOrig));
			
			ValidationResult result = 
				etdEngine.validateTD(td, issuerCert1[0], issuerCert1, 
						issuerCert3, new BinaryCertChainValidator(true));
			if (!result.isValid())
				fail(result.getInvalidResaon());
			assertEquals(4, td.getXMLBean().getAttributeStatementArray()[0].getAttributeArray().length);
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	
	@Test
	public void testRSACert3()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerCert1[0], issuerCert1,
					privKey1, issuerCert3, null);
			
			String dnsubFromTD = new X500Principal(td.getSubjectName()).getName();
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

	
	@Test
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

	
	@Test
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

	@Test
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

	@Test
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

	@Test
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
