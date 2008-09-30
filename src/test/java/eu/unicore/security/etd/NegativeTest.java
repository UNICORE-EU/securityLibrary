/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

import java.util.Calendar;
import java.util.Date;

import eu.unicore.security.CertificateUtils;
import eu.unicore.security.ValidationResult;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.etd.TrustDelegation;

/**
 * @author K. Benedyczak
 */
public class NegativeTest extends ETDTestBase
{
	public void testWrongCustodianDN()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, receiverDN1, null);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerDN2, issuerDN1, receiverDN1);
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

	public void testWrongCustodianCert()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerCert1[0], issuerCert1,
					privKey1, receiverCert1, null);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerCert2[0], issuerCert1, receiverCert1);
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

	public void testWrongIssuer()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, receiverDN1, null);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerDN1, issuerDN2, receiverDN1);
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

	public void testWrongReceiverDN()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, receiverDN1, null);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerDN1, issuerDN1, receiverDN2);
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

	public void testWrongReceiverCert()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerCert1[0], issuerCert1,
					privKey1, receiverCert1, null);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerCert1[0], issuerCert1, receiverCert2);
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

	
	public void testWrongKey()
	{
		try
		{
			TrustDelegation td = etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey3, receiverDN1, null);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerDN1, issuerDN1, receiverDN1);
			if (result.isValid() || 
				!result.getInvalidResaon().startsWith("Signature is incorrect"))
				fail("Validation of wrong key succeeded/error is wrong: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	public void testWrongEndDate()
	{
		try
		{
			Calendar c = Calendar.getInstance();
			c.add(Calendar.MINUTE, -1);
			Date d = new Date();
			
			DelegationRestrictions restrictions = new DelegationRestrictions(d, c.getTime(), -1);
			TrustDelegation td = etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, receiverDN1, restrictions);

			ValidationResult result = 
				etdEngine.validateTD(td, issuerDN1, issuerDN1, receiverDN1);
			if (result.isValid() || 
				!result.getInvalidResaon().startsWith("Delegation is no more valid"))
				fail("Validation of wrong end date succeeded/error is wrong: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

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
				etdEngine.validateTD(td, issuerDN1, issuerDN1, receiverDN1);
			if (result.isValid() || 
				!result.getInvalidResaon().startsWith("Delegation is not yet valid"))
				fail("Validation of wrong start date succeeded/error is wrong: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}


	public void testExpiredCertVerify()
	{
		try
		{
			System.setProperty(CertificateUtils.VERIFY_GENERATION_KEY, "false");
			TrustDelegation td = etdEngine.generateTD(expiredDN, expiredCert,
					privKeyExpired, receiverDN1, null);

			ValidationResult result = 
				etdEngine.validateTD(td, expiredDN, expiredDN, receiverDN1);
			if (result.isValid() || 
				!result.getInvalidResaon().startsWith("Issuer certificate is not valid"))
				fail("Validation of ETD issued with expired issuer's certificate is wrong: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	public void testExpiredCertGenerate()
	{
		try
		{
			System.setProperty(CertificateUtils.VERIFY_GENERATION_KEY, "true");

			etdEngine.generateTD(expiredDN, expiredCert, 
				privKeyExpired, receiverDN1, null);
			fail("Generation of ETD with expired issuer's certificate succeeded.");
		} catch (Exception e)
		{
			if (!(e instanceof DSigException) || 
				!e.getMessage().startsWith("Issuer ("))
				fail("Wrong error when generating ETD with expired cert: "
					+ e);
			
		}
		assertTrue(true);
	}



}
