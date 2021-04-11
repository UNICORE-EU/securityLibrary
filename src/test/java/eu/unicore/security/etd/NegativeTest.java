/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

import static org.junit.Assert.*;

import java.util.Calendar;
import java.util.Date;

import org.junit.Test;

import eu.emi.security.authn.x509.helpers.BinaryCertChainValidator;
import eu.unicore.security.ValidationResult;

public class NegativeTest extends ETDTestBase
{
	@Test
	public void testWrongCustodianDN()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, receiverDN1, null);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerDN2, issuerDN1, receiverDN1, new BinaryCertChainValidator(true));
			if (result.isValid() || 
				!result.getInvalidResaon().startsWith("Wrong custodian"))
				fail("Validation of wrong custodian succeeded/error is wrong: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void testWrongCustodianCert()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerCert1[0], issuerCert1,
					privKey1, receiverCert1, null);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerCert2[0], issuerCert1, receiverCert1, new BinaryCertChainValidator(true));
			if (result.isValid() || 
				!result.getInvalidResaon().startsWith("Wrong custodian"))
				fail("Validation of wrong custodian succeeded/error is wrong: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void testWrongIssuer()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, receiverDN1, null);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerDN1, issuerDN2, receiverDN1, new BinaryCertChainValidator(true));
			if (result.isValid() || 
				!result.getInvalidResaon().startsWith("Wrong issuer"))
				fail("Validation of wrong issuer succeeded/error is wrong: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void testWrongReceiverDN()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, receiverDN1, null);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerDN1, issuerDN1, receiverDN2, new BinaryCertChainValidator(true));
			if (result.isValid() || 
				!result.getInvalidResaon().startsWith("Wrong receiver"))
				fail("Validation of wrong receiver succeeded/error is wrong: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void testWrongReceiverCert()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerCert1[0], issuerCert1,
					privKey1, receiverCert1, null);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerCert1[0], issuerCert1, receiverCert2, new BinaryCertChainValidator(true));
			if (result.isValid() || 
				!result.getInvalidResaon().startsWith("Wrong delegation receiver"))
				fail("Validation of wrong receiver succeeded/error is wrong: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	
	@Test
	public void testWrongKey()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey3, receiverDN1, null);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerDN1, issuerDN1, receiverDN1, new BinaryCertChainValidator(true));
			if (result.isValid() || 
				!result.getInvalidResaon().contains("signature is incorrect"))
				fail("Validation of wrong key succeeded/error is wrong: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void testWrongEndDate()
	{
		try
		{
			Calendar c = Calendar.getInstance();
			c.add(Calendar.MINUTE, -6);
			Date d = new Date();
			
			DelegationRestrictions restrictions = new DelegationRestrictions(d, c.getTime(), -1);
			TrustDelegation td = etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, receiverDN1, restrictions);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerDN1, issuerDN1, receiverDN1, new BinaryCertChainValidator(true));
			if (result.isValid() || 
				!result.getInvalidResaon().contains("Assertion expired"))
				fail("Validation of wrong end date succeeded/error is wrong: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void testWrongStartDate()
	{
		try
		{
			Calendar c = Calendar.getInstance();
			c.add(Calendar.MINUTE, 10);
			Date dStart = c.getTime();
			c.add(Calendar.MINUTE, 1);
			
			DelegationRestrictions restrictions = new DelegationRestrictions(dStart, c.getTime(), -1);
			TrustDelegation td = etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, receiverDN1, restrictions);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerDN1, issuerDN1, receiverDN1, new BinaryCertChainValidator(true));
			if (result.isValid() || 
				!result.getInvalidResaon().contains("Assertion is not yet valid"))
				fail("Validation of wrong start date succeeded/error is wrong: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}


	@Test
	public void testExpiredCertVerify()
	{ 
		try
		{
			TrustDelegation td = etdEngine.generateTD(expiredDN, expiredCert,
					privKeyExpired, receiverDN1, null);
			ValidationResult result = 
				etdEngine.validateTD(td, expiredDN, expiredDN, receiverDN1,
					new BinaryCertChainValidator(false));
			if (result.isValid() || 
				!result.getInvalidResaon().contains("was conducted by an untrusted entity"))
				fail("Validation of ETD issued with expired issuer's certificate is wrong: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}
}
