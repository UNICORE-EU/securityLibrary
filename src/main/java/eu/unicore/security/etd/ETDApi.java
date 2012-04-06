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
import java.util.List;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.unicore.security.ValidationResult;
import eu.unicore.security.dsig.DSigException;

/**
 * ETD external interface.
 * <p>
 * There are two flavours of trust delegations that can be used (but exectly one kind 
 * can be used in a chain). In the first kind identity is specified by DNs only. In this
 * case Issuer certificate (or chain) is included in every assertion but receiver and
 * custodian are specified by DNs only. In the second case subject's certificate
 * and custodian's certificate hash are included in the assertion too.
 * @author K. Benedyczak
 */
public interface ETDApi
{
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
	 */
	public List<TrustDelegation> issueChainedTD(List<TrustDelegation> chain,
			X509Certificate []issuer, PrivateKey pk, String receiverDN, 
			DelegationRestrictions restrictions) 
		throws DSigException, InconsistentTDChainException;
	
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
			X509Certificate []issuer, PrivateKey pk,
			X509Certificate []receiver, DelegationRestrictions restrictions) 
		throws DSigException, InconsistentTDChainException, CertificateEncodingException;
	
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
	public TrustDelegation generateTD(String custodianDN, X509Certificate[] issuer, 
			PrivateKey pk, String receiverDN, DelegationRestrictions restrictions) 
		throws DSigException;

	
	/**
	 * Generates trust delegationin terms of certificates.
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
			PrivateKey pk, X509Certificate[] receiver, 
			DelegationRestrictions restrictions) 
		throws DSigException, CertificateEncodingException;
	
	/**
	 * Validate single trust delegation assertion. Checks if receiver has trust of custodian 
	 * delegated by issuer. This validation is done in terms of DNs.
	 *  
	 * @param td
	 * @param custodian
	 * @param issuer
	 * @param receiver
 	 * @param validator certificate chain validator, used to check issuer cert chain.
	 * @return
	 */
	public ValidationResult validateTD(TrustDelegation td, String custodian,
			String issuer, String receiver, X509CertChainValidator validator);

	/**
	 * Validate single trust delegation assertion. Checks if receiver has trust of custodian 
	 * delegated by issuer. This validation is done in terms of certificates and it is assumed
	 * that assertion includes necessary certificates.
	 *  
	 * @param td
	 * @param custodian
	 * @param issuer
	 * @param receiver
 	 * @param validator certificate chain validator, used to check issuer cert chain.
	 * @return
	 */
	public ValidationResult validateTD(TrustDelegation td, X509Certificate custodian,
			X509Certificate []issuer, X509Certificate []receiver, X509CertChainValidator validator);

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
			String user, X509CertChainValidator validator);

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
	public ValidationResult isTrustDelegated(List<TrustDelegation> td, X509Certificate[] subject, 
			X509Certificate[] user, X509CertChainValidator validator);
	
	/**
	 * Helper method to check if the subject is present in the chain. The chain is
	 * not checked for consistency, so it should be validated before.
	 * @return true if subject is present in chain
	 */
	public boolean isSubjectInChain(List<TrustDelegation> td, String subject);

}
