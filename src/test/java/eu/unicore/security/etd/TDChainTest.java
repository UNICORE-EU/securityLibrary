/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

import java.util.Date;
import java.util.List;
import java.util.Vector;

import eu.unicore.security.ValidationResult;
import eu.unicore.security.etd.DelegationRestrictions;
import eu.unicore.security.etd.TrustDelegation;

/**
 * @author K. Benedyczak
 */
public class TDChainTest extends ETDTestBase
{
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
				etdEngine.isTrustDelegated(chain, receiverCert2, issuerCert3);
			if (!result.isValid())
				fail("Normal chain validation failed: " + result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	

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
				etdEngine.isTrustDelegated(chain, receiverDN2, issuerDN1);
			if (!result.isValid())
				fail("Normal chain validation failed: " + result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

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
				etdEngine.isTrustDelegated(chain, receiverCert2, issuerCert1);
			if (!result.isValid())
				fail("Normal chain validation failed: " + result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

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
				etdEngine.isTrustDelegated(chain, receiverDN1, issuerDN1);
			if (!result.isValid())
				fail("Intermediary receiver verification failed: " + 
						result.getInvalidResaon());
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

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
				etdEngine.isTrustDelegated(chain, receiverDN2, issuerDN2);
			if (result.isValid() || !result.getInvalidResaon().equals("Wrong user"))
				fail("Chain with wrong issuer passed validation");
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

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
				etdEngine.isTrustDelegated(chain, receiverCert2, issuerCert2);
			if (result.isValid() || !result.getInvalidResaon().equals("Wrong user"))
				fail("Chain with wrong issuer passed validation");
		} catch (Exception e)
		{
			fail(e.getMessage());
		}
		assertTrue(true);
	}

	
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
				etdEngine.isTrustDelegated(chain, receiverDN2, issuerDN1);

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
