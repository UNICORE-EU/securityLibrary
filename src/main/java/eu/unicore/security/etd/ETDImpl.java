/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 24, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.apache.xmlbeans.XmlObject;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.validators.AssertionValidator;
import eu.unicore.security.ValidationResult;
import eu.unicore.security.dsig.DSigException;

/**
 * Implements logic to generate and validate trust delegation assertions.
 * @author K. Benedyczak
 */
public class ETDImpl implements ETDApi
{
	public static final int DEFAULT_VALIDITY_DAYS = 14;

	@Override
	public TrustDelegation generateTD(String custodian, X509Certificate []issuer, 
			PrivateKey pk, String subject, DelegationRestrictions restrictions) 
		throws DSigException
	{
		TrustDelegation td = new TrustDelegation(custodian);
		td.setX509Issuer(issuer[0].getSubjectX500Principal().getName());
		td.setX509Subject(subject);
		return addRestrictionsAndSign(td, issuer, pk, restrictions);
	}


	@Override
	public TrustDelegation generateBootstrapTD(String custodianDN, X509Certificate[] issuer,
			String issuerName, String issuerFormat, PrivateKey pk, String receiverDN,
			DelegationRestrictions restrictions) throws DSigException
	{
		TrustDelegation td = new TrustDelegation(custodianDN);
		td.setIssuer(issuerName, issuerFormat);
		td.setX509Subject(receiverDN);
		return addRestrictionsAndSign(td, issuer, pk, restrictions);
	}

	
	@Override
	public TrustDelegation generateTD(X509Certificate custodian, X509Certificate[] issuer,
			PrivateKey pk, X509Certificate[] receiver,
			DelegationRestrictions restrictions) throws DSigException,
			CertificateEncodingException
	{
		return generateTD(custodian.getSubjectX500Principal().getName(), 
				TrustDelegation.generateSha2Hash(custodian), 
				custodian.hashCode(), issuer, pk, receiver, restrictions,
				new ArrayList<SAMLAttribute>());
	}
	

	@Override
	public TrustDelegation generateTD(X509Certificate custodian, X509Certificate[] issuer,
			PrivateKey pk, X509Certificate[] receiver,
			DelegationRestrictions restrictions, List<SAMLAttribute> attributes)
			throws DSigException, CertificateEncodingException
	{
		return generateTD(custodian.getSubjectX500Principal().getName(), 
				TrustDelegation.generateSha2Hash(custodian), 
				custodian.hashCode(), issuer, pk, receiver, restrictions,
				attributes);
	}

	
	private TrustDelegation generateTD(String custodianDN, String sha2Hash, int legacyHash, 
		X509Certificate[] issuer, PrivateKey pk, X509Certificate[] receiver, 
		DelegationRestrictions restrictions, List<SAMLAttribute> attributes) 
		throws DSigException, CertificateEncodingException
	{
		TrustDelegation td = new TrustDelegation(custodianDN, sha2Hash, legacyHash);
		td.setX509Issuer(issuer[0].getSubjectX500Principal().getName());
		td.setX509Subject(receiver[0].getSubjectX500Principal().getName());
		td.setSenderVouchesX509Confirmation(receiver);
		for (SAMLAttribute sam : attributes) 
		{
			td.addAttribute(sam);
		}
		return addRestrictionsAndSign(td, issuer, pk, restrictions);
	}	
	
	private TrustDelegation addRestrictionsAndSign(TrustDelegation td, 
			X509Certificate []issuer, PrivateKey pk,
			DelegationRestrictions restrictions) 
		throws DSigException
	{
		if (restrictions == null)
		{
			Calendar c = Calendar.getInstance();
			c.add(Calendar.DATE, DEFAULT_VALIDITY_DAYS);
			restrictions = new DelegationRestrictions(new Date(), 
					c.getTime(), 1);
		}
		td.setTimeConditions(restrictions.getNotBefore(), 
				restrictions.getNotOnOrAfter());
		td.setProxyRestriction(restrictions.getMaxProxyCount());
		XmlObject[] customConds = restrictions.getCustomConditions();
		if (customConds != null)
			for (XmlObject c: customConds)
				td.addCustomCondition(c);
		
		td.sign(pk, issuer);
		return td;
	}
	

	@Override
	public List<TrustDelegation> issueChainedTD(List<TrustDelegation> chain,
			X509Certificate []issuer, PrivateKey pk,
			String subject, DelegationRestrictions restrictions) 
		throws DSigException, InconsistentTDChainException
	{
		if (chain == null || chain.size() == 0)
			throw new IllegalArgumentException("Trust delegation chain cant be empty");
		if (chain.get(0).getCustodianCertHash() != null)
			throw new InconsistentTDChainException();
		chain.add(generateTD(chain.get(0).getCustodianDN(), issuer, 
					pk, subject, restrictions));
		return chain;
	}
	

	@Override
	public List<TrustDelegation> issueChainedTD(List<TrustDelegation> chain, 
		X509Certificate[] issuer, PrivateKey pk, X509Certificate[] receiver, 
		DelegationRestrictions restrictions) 
		throws DSigException, InconsistentTDChainException, CertificateEncodingException
	{
		if (chain == null || chain.size() == 0)
			throw new IllegalArgumentException("Trust delegation chain cant be empty");
		if (chain.get(0).getCustodianCertHash() == null)
			throw new InconsistentTDChainException();
		TrustDelegation initial = chain.get(0);
		
		chain.add(generateTD(initial.getCustodianDN(), initial.getCustodianCertHashSha2(),
				initial.getCustodianCertHash(), issuer, pk, receiver, restrictions,
				new ArrayList<SAMLAttribute>()));
		return chain;
	}
	

	@Override
	public ValidationResult validateTD(TrustDelegation td, String custodian, 
			String issuer, String receiver, X509CertChainValidator validator)
	{
		NameIDType issuerN = NameIDType.Factory.newInstance();
		issuerN.setFormat(SAMLConstants.NFORMAT_DN);
		issuerN.setStringValue(issuer);
		return validateTD(td, custodian, issuerN, receiver, validator);
	}	

	public ValidationResult validateTD(TrustDelegation td, String custodian, 
			NameIDType issuer, String receiver, X509CertChainValidator validator)
	{
		NameIDType realIssuer = td.getXMLBean().getIssuer();
		String realIssuerNFormat = realIssuer.getFormat();
		if (realIssuerNFormat == null)
			realIssuerNFormat = SAMLConstants.NFORMAT_ENTITY;
		String requestedIssuerFormat = issuer.getFormat();
		if (requestedIssuerFormat == null)
			requestedIssuerFormat = SAMLConstants.NFORMAT_ENTITY;
		if (!requestedIssuerFormat.equals(realIssuerNFormat))
			return new ValidationResult(false, "Wrong issuer format (is " + realIssuerNFormat + 
					" and should be " + requestedIssuerFormat + ")");
		String i1 = realIssuer.getStringValue();
		if (realIssuerNFormat.equals(SAMLConstants.NFORMAT_DN))
		{
			if (!X500NameUtils.equal(i1, issuer.getStringValue()))
				return new ValidationResult(false, "Wrong issuer (is " + i1 + 
					" and should be " + issuer.getStringValue() + ")");
		} else
		{
			if (!i1.equals(issuer.getStringValue()))
				return new ValidationResult(false, "Wrong issuer (is " + i1 + 
						" and should be " + issuer.getStringValue() + ")");
		}

		String r1 = td.getSubjectName();
		if (!X500NameUtils.equal(r1, receiver))
			return new ValidationResult(false, "Wrong receiver (is " + r1 + 
					" and should be " + receiver + ")");
		
		X509Certificate []issuerCert = td.getIssuerFromSignature();
		if (issuerCert == null || issuerCert.length == 0)
			return new ValidationResult(false, "Lack of issuer certificate " +
				"(neither in KeyInfo element nor in available certificates list)");
		
		return validateTDBasic(validator, td, issuerCert, custodian, null, null);
	}


	@Override
	public ValidationResult validateTD(TrustDelegation td, X509Certificate custodian, 
			X509Certificate[] issuer, X509Certificate[] receiver, X509CertChainValidator validator)
	{
		if (issuer == null || issuer.length == 0)
			throw new IllegalArgumentException("Issuer argument must not be null/empty");
		if (receiver == null || receiver.length == 0)
			throw new IllegalArgumentException("Receiver argument must not be null/empty");
		X509Certificate[] issuerFromTD = td.getIssuerFromSignature();
		if (issuerFromTD == null || issuerFromTD.length == 0)
			return new ValidationResult(false, "No issuer certificate in trust " +
					"delegation assertion");
		X509Certificate[] subjectFromTD = td.getSubjectFromConfirmation();
		if (subjectFromTD == null || subjectFromTD.length == 0)
			return new ValidationResult(false, "No receiver certificate in trust " +
					"delegation assertion");
		if (!compareChains(issuer, issuerFromTD)) 
			return new ValidationResult(false, "Wrong delegation issuer " +
					"(TD issuer certificate: [" + issuerFromTD[0].toString() +
					"] and should be: [" +issuer[0].toString() + "])");
		if (!compareChains(receiver, subjectFromTD))
			return new ValidationResult(false, "Wrong delegation receiver " +
					"(TD receiver certificate: [" + subjectFromTD[0].toString() +
					"] and should be: [" +receiver[0].toString() + "])");
		return validateTDBasic(validator, td, issuer, custodian.getSubjectX500Principal().getName(),
				custodian.hashCode(), TrustDelegation.generateSha2Hash(custodian));
	}
	
	
	private ValidationResult validateTDBasic(X509CertChainValidator validator, TrustDelegation td, 
			X509Certificate[] issuer, String custodianDN, Integer custodianHash, String custodianHashSha2)
	{
		String c1 = td.getCustodianDN();
		if (!X500NameUtils.equal(c1, custodianDN))
			return new ValidationResult(false, "Wrong custodian (is " + c1 + 
					" should be " + custodianDN);
		if (custodianHash != null)
		{
			Integer i = td.getCustodianCertHash();
			if (i == null)
				return new ValidationResult(false, "Custodian in assertion doesn't" +
						"contain certificate hash");
			if (!i.equals(custodianHash))
				return new ValidationResult(false, "Wrong custodian (certificate" +
						" hashes are different)");				
		}

		if (custodianHashSha2 != null)
		{
			String h = td.getCustodianCertHashSha2();
			/* For now this code is disabled. When enabled, U6 based clients working with delegation
			 * in certificate mode won't work with U7 servers. This rather shouldn't be a case, 
			 * but for now allow for the legacy assertions.
			if (h == null)
				return new ValidationResult(false, "Custodian in assertion doesn't" +
						"contain certificate SHA2 hash");
			*/
			if (h!= null && !h.equals(custodianHashSha2))
				return new ValidationResult(false, "Wrong custodian (certificate" +
						" SHA2 hashes are different)");				
		}

		AssertionValidator asValidator = new AssertionValidator(null, null, null,
				AssertionValidator.DEFAULT_VALIDITY_GRACE_PERIOD, 
				new ETDSamlTrustChecker(validator, issuer));
		try
		{
			asValidator.validate(td.getXMLBeanDoc());
		} catch (SAMLValidationException e)
		{
			return new ValidationResult(false, "Delegation assertion is invalid: " + 
					e.getMessage());
		}
		
		return new ValidationResult(true, "Validation OK");
	}
	

	@Override
	public ValidationResult isTrustDelegated(List<TrustDelegation> td, String subject, 
			String user, X509CertChainValidator validator, Collection<X509Certificate> trustedIssuers)
	{
		if (td == null || subject == null || user == null)
			return new ValidationResult(false, "Some of arguments are null");
		if (td.size() == 0)
			return new ValidationResult(false, "Delegation chain is empty");
		TrustDelegation initial = td.get(0);
		String custodian = initial.getCustodianDN();
		if (!X500NameUtils.equal(user, custodian))
			return new ValidationResult(false, "Wrong user, it is not equal to custodian, user is: " + 
					user + " while custodian is: " + custodian);
		X509Certificate []custodianCert = initial.getIssuerFromSignature();
		if (custodianCert == null || custodianCert.length == 0)
			return new ValidationResult(false, "No issuer certificate at position 1.");
		if (!isAmongTrusted(custodianCert[0], trustedIssuers))
		{
			if (!X500NameUtils.equal(custodianCert[0].getSubjectX500Principal(), custodian))
				return new ValidationResult(false, "The issuer's certificate of the initial trust delegation" +
					" is not consistent with the declared custodian (subject) and it is not among trusted 3rd party issuers");
			if (!X500NameUtils.equal(custodian, initial.getIssuerName()))
				return new ValidationResult(false, "The signer's certificate of the initial trust delegation" +
					" is not consistent with the declared assertion issuer and it is not among trusted 3rd party issuers");
		}

		
		int i=0;
		int []maxProxies = new int[td.size()]; 
		for (; i<td.size(); i++)
		{
			TrustDelegation cur = td.get(i);
			if (i + 1 < td.size())
				if (!X500NameUtils.equal(cur.getSubjectName(), td.get(i+1).getIssuerName()))
					return new ValidationResult(
						false, "Chain is inconsistent at position " + i + 
							", subject and issuer do not match. Subject is: " + 
							cur.getSubjectName() + 
							" while the issuer of the next delegation in chain is: " + 
							td.get(i+1).getIssuerName());
			String receiver = subject;
			if (i + 1 < td.size())
				receiver = td.get(i+1).getIssuerName();
			
			ValidationResult singleTD = validateTD(cur, custodian, 
				cur.getXMLBean().getIssuer(), receiver, validator);
			if (!singleTD.isValid())
				return new ValidationResult(false, 
						"Chain has invalid entry at position "
						+ i + ": " + singleTD.getInvalidResaon());
			
			maxProxies[i] = cur.getProxyRestriction();
			
			if (X500NameUtils.equal(subject, cur.getSubjectName()))
				break;
		}
		if (i == td.size())
			return new ValidationResult(false, "Wrong subject");
		
		for (int j=0; j<i; j++)
			if (maxProxies[j] > 0 && maxProxies[j] < (i-j+1))
				return new ValidationResult(false, "Chain length " +
					"exceedes maximum proxy restriction of " +
					"assertion at position " + j);
		
		return new ValidationResult(true, "Validation OK");
	}
	

	@Override
	public ValidationResult isTrustDelegated(List<TrustDelegation> td, 
			X509Certificate[] subject, X509Certificate[] user, X509CertChainValidator validator, 
			Collection<X509Certificate> trustedIssuers)
	{
		if (td == null || subject == null || user == null || 
				user.length == 0 || subject.length == 0)
			return new ValidationResult(false, "Some of arguments are null/empty");
		if (td.size() == 0)
			return new ValidationResult(false, "Delegation chain is empty");
		X509Certificate []initIssuerCert = td.get(0).getIssuerFromSignature();
		if (!isAmongTrusted(initIssuerCert[0], trustedIssuers))
		{
			if (!user[0].equals(initIssuerCert[0]))
				return new ValidationResult(false, "The signer's certificate of the initial trust delegation" +
						" is not consistent with the declared assertion issuer certificate and it is not among trusted 3rd party issuers");
		}

		int i=0;
		int []maxProxies = new int[td.size()]; 
		for (; i<td.size(); i++)
		{
			TrustDelegation cur = td.get(i);
			X509Certificate[] curSubject = cur.getSubjectFromConfirmation();
			if (curSubject == null || curSubject.length == 0)
				return new ValidationResult(
						false, "No subject certificate at position " + i);
			X509Certificate[] nextIssuer = null;
			if (i + 1 < td.size())
			{
				nextIssuer = td.get(i+1).getIssuerFromSignature();
				if (nextIssuer == null || nextIssuer.length == 0)
					return new ValidationResult(
						false, "No issuer certificate at position " + (i+1));
				if (!compareChains(curSubject, nextIssuer))
					return new ValidationResult(
						false, "Chain is inconsistent at position " + i + 
						" issuer's and subject's certificates do not match");
			}
			X509Certificate[] curIssuer = cur.getIssuerFromSignature();
			if (curIssuer == null || curIssuer.length == 0)
				return new ValidationResult(false, 
						"No issuer certificate at position " + i);
			ValidationResult singleTD = validateTD(cur, user[0], 
				curIssuer, curSubject, validator);
			if (!singleTD.isValid())
				return new ValidationResult(false, 
						"Chain has invalid entry at position "
						+ i + ": " + singleTD.getInvalidResaon());
			
			maxProxies[i] = cur.getProxyRestriction();
			if (compareChains(subject, curSubject))
				break;
		}
		
		
		if (i == td.size())
			return new ValidationResult(false, "Wrong subject");
		
		for (int j=0; j<i; j++)
			if (maxProxies[j] > 0 && maxProxies[j] < (i-j+1))
				return new ValidationResult(false, "Chain length " +
					"exceedes maximum proxy restriction of " +
					"assertion at position " + j);
		
		return new ValidationResult(true, "Validation OK");
	}
	
	private boolean compareChains(X509Certificate []chain1, 
			X509Certificate []chain2)
	{
		if (chain1.length != chain2.length)
			return false;
		for (int i=0; i<chain1.length; i++)
			if (!chain1[i].equals(chain2[i]))
				return false;
		return true;
	}

	@Override
	public boolean isSubjectInChain(List<TrustDelegation> tdChain, String subject)
	{
		for (TrustDelegation td: tdChain)
		{
			if (X500NameUtils.equal(td.getSubjectName(), subject))
				return true;
		}
		return false;
	}
	
	private boolean isAmongTrusted(X509Certificate toCheck, Collection<X509Certificate> trusted)
	{
		for (X509Certificate t: trusted)
			if (t.equals(toCheck))
				return true;
		return false;
	}
}







