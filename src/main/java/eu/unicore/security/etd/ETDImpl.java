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
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.xmlbeans.XmlObject;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.X500NameUtils;
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

	/**
	 * Generates trust delegation in terms of DNs.
	 * @param custodianDN DN of initial trust delegation issuer (if not in trust delegation 
	 * chain then it is equal to issuer's DN)
	 * @param issuer Actual issuer of this trust delegation
	 * @param pk Private key of the issuer
	 * @param receiverDN DN of the receiver of this trust delegation
	 * @param restrictions Set of restrictions (can be null)
	 * @return The new trust delegation
	 * @throws DSigException
	 */
	public TrustDelegation generateTD(String custodian, X509Certificate []issuer, 
			PrivateKey pk, String subject, DelegationRestrictions restrictions) 
		throws DSigException
	{
		TrustDelegation td = new TrustDelegation(custodian);
		td.setX509Issuer(issuer[0].getSubjectX500Principal().getName());
		td.setX509Subject(subject);
		return addRestrictionsAndSign(td, issuer, pk, restrictions);
	}

	/**
	 * Generates trust delegation in terms of certificates.
	 * @param custodian DN of initial trust delegation issuer (if not in trust delegation chain 
	 * it is equal to issuer)
	 * @param issuer Actual issuer certificate of this trust delegation
	 * @param pk Private key of issuer
	 * @param receiver The receiver of this trust delegation
	 * @param restrictions Set of restrictions (can be null)
	 * @return The new trust delegation
	 * @throws DSigException
	 * @throws CertificateEncodingException 
	 */
	public TrustDelegation generateTD(X509Certificate custodian, X509Certificate[] issuer, 
		PrivateKey pk, X509Certificate[] receiver, DelegationRestrictions restrictions) 
		throws DSigException, CertificateEncodingException
	{
		TrustDelegation td = new TrustDelegation(custodian);
		td.setX509Issuer(issuer[0].getSubjectX500Principal().getName());
		td.setX509Subject(receiver[0].getSubjectX500Principal().getName());
		td.setSenderVouchesX509Confirmation(receiver);
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
	
	
	/**
	 * Extends existing delegation chain by adding the next entry, that further delegates trust
	 * to the receiver. Generated assertion will hold DNs.
	 * @param chain
	 * @param pk
	 * @param receiverDN
	 * @param restrictions
	 * @return
	 * @throws DSigException
	 * @throws InconsistentTDChainException
	 * @throws IllegalArgumentException
	 */
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
	
	
	/**
	 * Extends existing delegation chain by adding the next entry, that further delegates trust
	 * to the receiver. Generated assertion will hold full certificates.
	 * @param chain
	 * @param issuer
	 * @param pk
	 * @param receiver
	 * @param restrictions
	 * @return
	 * @throws DSigException
	 * @throws InconsistentTDChainException
	 * @throws CertificateEncodingException 
	 */
	public List<TrustDelegation> issueChainedTD(List<TrustDelegation> chain, 
		X509Certificate[] issuer, PrivateKey pk, X509Certificate[] receiver, 
		DelegationRestrictions restrictions) 
		throws DSigException, InconsistentTDChainException, CertificateEncodingException
	{
		if (chain == null || chain.size() == 0)
			throw new IllegalArgumentException("Trust delegation chain cant be empty");
		if (chain.get(0).getCustodianCertHash() == null)
			throw new InconsistentTDChainException();
		//FIXME - assumes that issuer of the first ETD == custodian. Not compatible with bootstrap ETD.
		X509Certificate[] custodian = chain.get(0).getIssuerFromSignature();
		if (custodian == null || custodian.length == 0)
			throw new InconsistentTDChainException();
		
		chain.add(generateTD(custodian[0], issuer, pk, receiver, restrictions));
		return chain;
	}
	

	
	
	/**
	 * Validate single trust delegation assertion. Checks if receiver has trust of custodian 
	 * delegated by issuer. This validation is done in terms of DNs.
	 *  
	 * @param td
	 * @param custodian
	 * @param issuer
	 * @param receiver
 	 * @param validator certificate chain validator, used to check issuer cert chain
 	 * received from the assertion
	 * @return
	 */
	public ValidationResult validateTD(TrustDelegation td, String custodian, 
			String issuer, String receiver, X509CertChainValidator validator)
	{
		String i1 = td.getIssuerDN();
		if (!X500NameUtils.equal(i1, issuer))
			return new ValidationResult(false, "Wrong issuer (is " + i1 + 
					" and should be " + issuer + ")");
		String r1 = td.getSubjectDN();
		if (!X500NameUtils.equal(r1, receiver))
			return new ValidationResult(false, "Wrong receiver (is " + r1 + 
					" and should be " + receiver + ")");
		
		X509Certificate []issuerCert = td.getIssuerFromSignature();
		if (issuerCert == null || issuerCert.length == 0)
			return new ValidationResult(false, "Lack of issuer certificate " +
				"(neither in KeyInfo element nor in available certificates list)");
		
		return validateTDBasic(validator, td, issuerCert, custodian, null, null);
	}

	
	/**
	 * Validate single trust delegation assertion. Checks if receiver has trust of custodian 
	 * delegated by issuer. This validation is done in terms of certificates and it is assumed
	 * that assertion includes necessary certificates.
	 *  
	 * @param td
	 * @param custodian
	 * @param issuer expected issuer certificate chain (it is verified if it is a valid chain).
	 * @param receiver
	 * @param validator certificate chain validator, used to check issuer cert chain.
	 * @return
	 */
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
	
	/**
	 * Tests if the specified trust delegation chain delegates the trust from user to
	 * subject. 
	 * <p>
	 * Please note that if the subject is the receiver of the assertion that is not
	 * the last one in the chain, then the rest of the chain not need to be checked 
	 * (and can be theoretically invalid).
	 * <p>
	 * This validation is done in terms of DNs.
	 * @param td
	 * @param subject
	 * @param user
	 * @param validator certificate chain validator, used to check issuer cert chain.
	 * @return validation result
	 */
	public ValidationResult isTrustDelegated(List<TrustDelegation> td, String subject, 
			String user, X509CertChainValidator validator)
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
		
		if (!X500NameUtils.equal(custodianCert[0].getSubjectX500Principal(), custodian))
			return new ValidationResult(false, "The issuer's certificate of the initial trust delegation" +
					" is not consistent with the declared custodian (subject)");
		if (!X500NameUtils.equal(custodian, initial.getIssuerDN()))
			return new ValidationResult(false, "The signer's certificate of the initial trust delegation" +
					" is not consistent with the declared assertion issuer");

		
		int i=0;
		int []maxProxies = new int[td.size()]; 
		for (; i<td.size(); i++)
		{
			TrustDelegation cur = td.get(i);
			if (i + 1 < td.size())
				if (!X500NameUtils.equal(cur.getSubjectDN(), td.get(i+1).getIssuerDN()))
					return new ValidationResult(
						false, "Chain is inconsistent at position " + i + 
							", subject and issuer do not match. Subject is: " + 
							cur.getSubjectDN() + 
							" while the issuer of the next delegation in chain is: " + 
							td.get(i+1).getIssuerDN());
			String receiver = subject;
			if (i + 1 < td.size())
				receiver = td.get(i+1).getIssuerDN();
			
			ValidationResult singleTD = validateTD(cur, custodian, 
				cur.getIssuerDN(), receiver, validator);
			if (!singleTD.isValid())
				return new ValidationResult(false, 
						"Chain has invalid entry at position "
						+ i + ": " + singleTD.getInvalidResaon());
			
			maxProxies[i] = cur.getProxyRestriction();
			
			if (X500NameUtils.equal(subject, cur.getSubjectDN()))
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
	
	/**
	 * Tests if the specified trust delegation chain delegates the trust from user to
	 * subject. Please note that if the subject is the receiver of the assertion that is not
	 * the last one in the chain, then the rest of the chain not need to be checked 
	 * (and can be theoretically invalid).
	 * This validation is done in terms of certificates.
	 * @param td
	 * @param subject
	 * @param user
	 * @param validator certificate chain validator, used to check issuer cert chain.
	 * @return validation result
	 */
	public ValidationResult isTrustDelegated(List<TrustDelegation> td, 
			X509Certificate[] subject, X509Certificate[] user, X509CertChainValidator validator)
	{
		if (td == null || subject == null || user == null || 
				user.length == 0 || subject.length == 0)
			return new ValidationResult(false, "Some of arguments are null/empty");
		if (td.size() == 0)
			return new ValidationResult(false, "Delegation chain is empty");
		TrustDelegation initial = td.get(0);
		String custodian = initial.getCustodianDN();
		X500Principal u = user[0].getSubjectX500Principal();
		if (!X500NameUtils.equal(u, custodian))
			return new ValidationResult(false, "Wrong user");
		Integer custodianHash = initial.getCustodianCertHash();
		if (custodianHash == null)
			return new ValidationResult(false, "Initial delegation doesn't have " +
					"custodian certificate hash.");
		if (!custodianHash.equals(user[0].hashCode()))
			return new ValidationResult(false, "Wrong user (certificate hashes " +
					"are different)");
		//FIXME - assumes that issuer of the first ETD == custodian. Not compatible with bootstrap ETD.
		X509Certificate []custodianCert = initial.getIssuerFromSignature();
		if (custodianCert == null || custodianCert.length == 0)
			return new ValidationResult(false, "No issuer certificate at position 1.");
		
		if (!X500NameUtils.equal(custodianCert[0].getSubjectX500Principal(), custodian))
			return new ValidationResult(false, "The issuer's certificate of the initial trust delegation" +
					" is not consistent with the declared custodian (subject)");
		if (custodianCert[0].hashCode() != custodianHash)
			return new ValidationResult(false, "The issuer's certificate of the initial trust delegation" +
					" is not consistent with the declared custodian (hash)");
		if (!X500NameUtils.equal(custodianCert[0].getIssuerX500Principal(), initial.getIssuerDN()))
			return new ValidationResult(false, "The signer's certificate of the initial trust delegation" +
					" is not consistent with the declared assertion issuer");
		
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
			ValidationResult singleTD = validateTD(cur, custodianCert[0], 
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
			if (X500NameUtils.equal(td.getSubjectDN(), subject))
				return true;
		}
		return false;
	}
}







