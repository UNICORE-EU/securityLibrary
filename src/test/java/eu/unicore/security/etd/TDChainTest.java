/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

import static org.junit.Assert.*;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Vector;

import org.junit.Test;

import eu.emi.security.authn.x509.helpers.BinaryCertChainValidator;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.security.ValidationResult;
import eu.unicore.security.etd.DelegationRestrictions;
import eu.unicore.security.etd.TrustDelegation;

/**
 * @author K. Benedyczak
 */
public class TDChainTest extends ETDTestBase
{
	@Test
	public void testNormalCert2()
	{
		try
		{
			DelegationRestrictions restrictions = new DelegationRestrictions(
					new Date(), 1, 3);
			Vector<TrustDelegation> td = new Vector<TrustDelegation>();
			td.add(etdEngine.generateTD(issuerCert3[0], issuerCert3,
					privKey4, issuerCert2, restrictions));
			restrictions.setMaxProxyCount(2);
			List<TrustDelegation> chain = etdEngine.issueChainedTD(td, 
					issuerCert2, privKey2, receiverCert1, restrictions);
			chain = etdEngine.issueChainedTD(chain, 
					receiverCert1, privKey3, receiverCert2, null);
			
			ValidationResult result = 
				etdEngine.isTrustDelegated(chain, receiverCert2, issuerCert3, new BinaryCertChainValidator(true),
						new HashSet<X509Certificate>());
			if (!result.isValid())
				fail("Normal chain validation failed: " + result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	

	@Test
	public void testNormalDN()
	{
		try
		{
			DelegationRestrictions restrictions = new DelegationRestrictions(
					new Date(), 1, 3);
			Vector<TrustDelegation> td = new Vector<TrustDelegation>();
			td.add(etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, issuerDN2, restrictions));
			restrictions.setMaxProxyCount(2);
			List<TrustDelegation> chain = etdEngine.issueChainedTD(td, 
					issuerCert2, privKey2, receiverDN1, restrictions);
			chain = etdEngine.issueChainedTD(chain, 
					receiverCert1, privKey3, receiverDN2, null);
			
			ValidationResult result = 
				etdEngine.isTrustDelegated(chain, receiverDN2, issuerDN1, new BinaryCertChainValidator(true),
						new HashSet<X509Certificate>());
			if (!result.isValid())
				fail("Normal chain validation failed: " + result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void testNormalCert()
	{
		try
		{
			DelegationRestrictions restrictions = new DelegationRestrictions(
					new Date(), 1, 3);
			Vector<TrustDelegation> td = new Vector<TrustDelegation>();
			td.add(etdEngine.generateTD(issuerCert1[0], issuerCert1,
					privKey1, issuerCert2, restrictions));
			restrictions.setMaxProxyCount(2);
			List<TrustDelegation> chain = etdEngine.issueChainedTD(td, 
					issuerCert2, privKey2, receiverCert1, restrictions);
			chain = etdEngine.issueChainedTD(chain, 
					receiverCert1, privKey3, receiverCert2, null);
			
			ValidationResult result = 
				etdEngine.isTrustDelegated(chain, receiverCert2, issuerCert1, new BinaryCertChainValidator(true),
						new HashSet<X509Certificate>());
			if (!result.isValid())
				fail("Normal chain validation failed: " + result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void test2()
	{
		try
		{
			DelegationRestrictions restrictions = new DelegationRestrictions(
					new Date(), 1, 3);
			Vector<TrustDelegation> td = new Vector<TrustDelegation>();
			td.add(etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, issuerDN2, restrictions));
			restrictions.setMaxProxyCount(2);
			List<TrustDelegation> chain = etdEngine.issueChainedTD(td, 
					issuerCert2, privKey2, receiverDN1, restrictions);
			chain = etdEngine.issueChainedTD(chain, 
					receiverCert1, privKey3, receiverDN2, null);
			
			ValidationResult result = 
				etdEngine.isTrustDelegated(chain, receiverDN1, issuerDN1, new BinaryCertChainValidator(true),
						new HashSet<X509Certificate>());
			if (!result.isValid())
				fail("Intermediary receiver verification failed: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void testWrongUserDN()
	{
		try
		{
			DelegationRestrictions restrictions = new DelegationRestrictions(
					new Date(), 1, 3);
			Vector<TrustDelegation> td = new Vector<TrustDelegation>();
			td.add(etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, issuerDN2, restrictions));
			restrictions.setMaxProxyCount(2);
			List<TrustDelegation> chain = etdEngine.issueChainedTD(td, 
					issuerCert2, privKey2, receiverDN1, restrictions);
			chain = etdEngine.issueChainedTD(chain, 
					receiverCert1, privKey3, receiverDN2, null);
			
			ValidationResult result = 
				etdEngine.isTrustDelegated(chain, receiverDN2, issuerDN2, new BinaryCertChainValidator(true),
						new HashSet<X509Certificate>());
			if (result.isValid() || !result.getInvalidResaon().contains("Wrong user"))
				fail("Chain with wrong user passed validation: " + result);
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void testWrongUserCert()
	{
		try
		{
			DelegationRestrictions restrictions = new DelegationRestrictions(
					new Date(), 1, 3);
			Vector<TrustDelegation> td = new Vector<TrustDelegation>();
			td.add(etdEngine.generateTD(issuerCert1[0], issuerCert1,
					privKey1, issuerCert2, restrictions));
			restrictions.setMaxProxyCount(2);
			List<TrustDelegation> chain = etdEngine.issueChainedTD(td, 
					issuerCert2, privKey2, receiverCert1, restrictions);
			chain = etdEngine.issueChainedTD(chain, 
					receiverCert1, privKey3, receiverCert2, null);
			
			ValidationResult result = 
				etdEngine.isTrustDelegated(chain, receiverCert2, issuerCert2, new BinaryCertChainValidator(true),
						new HashSet<X509Certificate>());
			if (result.isValid() || !result.getInvalidResaon().contains("initial trust delegation is not consistent with the declared assertion issuer certificate and it is not among"))
				fail("Chain with wrong issuer passed validation:  " + result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void testWrongCustodianDN()
	{
		try
		{
			DelegationRestrictions restrictions = new DelegationRestrictions(
					new Date(), 1, 3);
			Vector<TrustDelegation> td = new Vector<TrustDelegation>();
			td.add(etdEngine.generateTD("CN=fake", issuerCert1,
					privKey1, issuerDN2, restrictions));
			List<TrustDelegation> chain = etdEngine.issueChainedTD(td, 
					issuerCert2, privKey2, receiverDN1, restrictions);
			chain = etdEngine.issueChainedTD(chain, 
					receiverCert1, privKey3, receiverDN2, restrictions);
			
			ValidationResult result = etdEngine.isTrustDelegated(chain, receiverDN2, "CN=fake", 
						new BinaryCertChainValidator(true),
						new HashSet<X509Certificate>());
			if (result.isValid() || !result.getInvalidResaon().contains("declared custodian (subject)"))
				fail("Chain with wrong custodian passed validation: " + result);

			ValidationResult result2 = etdEngine.isTrustDelegated(chain, receiverDN2, issuerDN2, 
					new BinaryCertChainValidator(true),
					new HashSet<X509Certificate>());
			if (result2.isValid() || !result2.getInvalidResaon().contains("Wrong user"))
				fail("Chain with wrong custodian passed validation: " + result2);
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void testBootstrapCustodianDN()
	{
		try
		{
			DelegationRestrictions restrictions = new DelegationRestrictions(
					new Date(), 1, 3);
			Vector<TrustDelegation> td = new Vector<TrustDelegation>();
			td.add(etdEngine.generateTD("CN=fake", issuerCert1,
					privKey1, issuerDN2, restrictions));
			List<TrustDelegation> chain = etdEngine.issueChainedTD(td, 
					issuerCert2, privKey2, receiverDN1, restrictions);
			chain = etdEngine.issueChainedTD(chain, 
					receiverCert1, privKey3, receiverDN2, restrictions);
			
			ValidationResult result = etdEngine.isTrustDelegated(chain, receiverDN2, "CN=fake", 
						new BinaryCertChainValidator(true),
						Collections.singleton(issuerCert1[0]));
			if (!result.isValid())
				fail("Chain with bootstrap issuer didn't pass validation: " + result);

			ValidationResult result2 = etdEngine.isTrustDelegated(chain, receiverDN2, issuerDN2, 
					new BinaryCertChainValidator(true),
					Collections.singleton(issuerCert1[0]));
			if (result2.isValid() || !result2.getInvalidResaon().contains("Wrong user"))
				fail("Chain with wrong custodian passed validation: " + result2);
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void testBootstrapCustodianEntity()
	{
		try
		{
			DelegationRestrictions restrictions = new DelegationRestrictions(
					new Date(), 1, 3);
			Vector<TrustDelegation> td = new Vector<TrustDelegation>();
			td.add(etdEngine.generateBootstrapTD("CN=fake", issuerCert1, "someIDP", SAMLConstants.NFORMAT_ENTITY,
					privKey1, issuerDN2, restrictions));
			List<TrustDelegation> chain = etdEngine.issueChainedTD(td, 
					issuerCert2, privKey2, receiverDN1, restrictions);
			chain = etdEngine.issueChainedTD(chain, 
					receiverCert1, privKey3, receiverDN2, restrictions);
			
			ValidationResult result = etdEngine.isTrustDelegated(chain, receiverDN2, "CN=fake", 
						new BinaryCertChainValidator(true),
						Collections.singleton(issuerCert1[0]));
			if (!result.isValid())
				fail("Chain with bootstrap issuer didn't pass validation: " + result);

			ValidationResult result2 = etdEngine.isTrustDelegated(chain, receiverDN2, issuerDN2, 
					new BinaryCertChainValidator(true),
					Collections.singleton(issuerCert1[0]));
			if (result2.isValid() || !result2.getInvalidResaon().contains("Wrong user"))
				fail("Chain with wrong custodian passed validation: " + result2);
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void testWrongCustodianCert()
	{
		try
		{
			DelegationRestrictions restrictions = new DelegationRestrictions(
					new Date(), 1, 3);
			Vector<TrustDelegation> td = new Vector<TrustDelegation>();
			td.add(etdEngine.generateTD(issuerCert3[0], issuerCert1,
					privKey1, issuerCert2, restrictions));
			List<TrustDelegation> chain = etdEngine.issueChainedTD(td, 
					issuerCert2, privKey2, receiverCert1, restrictions);
			chain = etdEngine.issueChainedTD(chain, 
					receiverCert1, privKey3, receiverCert2, null);
			
			ValidationResult result = etdEngine.isTrustDelegated(chain, receiverCert2, issuerCert2, 
						new BinaryCertChainValidator(true),
						new HashSet<X509Certificate>());
			if (result.isValid())
				fail("Chain with wrong custodian passed validation: " + result);

			ValidationResult result2 = etdEngine.isTrustDelegated(chain, receiverCert2, issuerCert3, 
					new BinaryCertChainValidator(true),
					new HashSet<X509Certificate>());
			if (result2.isValid() || !result2.getInvalidResaon().contains("initial trust delegation is not consistent with the declared assertion issuer certificate and it is not among"))
				fail("Chain with wrong custodian passed validation: " + result);
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	@Test
	public void testBootstrapCustodianCert()
	{
		try
		{
			DelegationRestrictions restrictions = new DelegationRestrictions(
					new Date(), 1, 3);
			Vector<TrustDelegation> td = new Vector<TrustDelegation>();
			td.add(etdEngine.generateTD(issuerCert3[0], issuerCert1,
					privKey1, issuerCert2, restrictions));
			List<TrustDelegation> chain = etdEngine.issueChainedTD(td, 
					issuerCert2, privKey2, receiverCert1, restrictions);
			chain = etdEngine.issueChainedTD(chain, 
					receiverCert1, privKey3, receiverCert2, null);
			
			ValidationResult result = etdEngine.isTrustDelegated(chain, receiverCert2, issuerCert2, 
						new BinaryCertChainValidator(true),
						Collections.singleton(issuerCert1[0]));
			if (result.isValid())
				fail("Chain with unwanted custodian pass validation: " + result);

			ValidationResult result2 = etdEngine.isTrustDelegated(chain, receiverCert2, issuerCert3, 
					new BinaryCertChainValidator(true),
					Collections.singleton(issuerCert1[0]));
			if (!result2.isValid())
				fail("Chain with bootstrap issuer didn't pass validation: " + result);
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}


	@Test
	public void testProxyLimit()
	{
		try
		{
			DelegationRestrictions restrictions = new DelegationRestrictions(
					new Date(), 1, -1);
			Vector<TrustDelegation> td = new Vector<TrustDelegation>();
			td.add(etdEngine.generateTD(issuerDN1, issuerCert1,
					privKey1, issuerDN2, restrictions));
			restrictions.setMaxProxyCount(1);
			List<TrustDelegation> chain = etdEngine.issueChainedTD(td, 
					issuerCert2, privKey2, receiverDN1, restrictions);
			chain = etdEngine.issueChainedTD(chain, 
					receiverCert1, privKey3, receiverDN2, null);
			
			ValidationResult result = 
				etdEngine.isTrustDelegated(chain, receiverDN2, issuerDN1, new BinaryCertChainValidator(true),
						new HashSet<X509Certificate>());

			if (result.isValid() || !result.getInvalidResaon().equals(
					"Chain length exceedes maximum proxy restriction of " +
					"assertion at position 1"))
				fail("Proxy limit test failed: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}
}
