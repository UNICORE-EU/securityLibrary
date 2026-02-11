package eu.unicore.security.etd;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.security.ValidationResult;
import eu.unicore.security.dsig.DSigException;

/**
 * ETD external interface.
 * <p>
 * There are two flavours of trust delegations that can be used (but exactly one kind 
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
	 * @return trust delegation chain
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
	 * @return trust delegation chain
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
	 * Generates a bootstrap trust delegation in terms of DNs. Bootstrap delegation
	 * is intended to be a first in chain, and additionally its issuer != custodian. Such issuer must be 
	 * explicitly trusted by validating entities. Initial issuer need not to be of X500 format, typically
	 * it will be of entity format.
	 * @param custodianDN DN of initial trust delegation issuer (if not in trust delegation 
	 * chain then it is equal to issuer's DN)
	 * @param issuer Actual issuer certificate of this trust delegation
	 * @param issuerName Issuer's identity
	 * @param issuerFormat Issuer's identity format
	 * @param pk Private key of the issuer
	 * @param receiverDN DN of the receiver of this trust delegation
	 * @param restrictions Set of restrictions (can be null)
	 * @return The new trust delegation
	 * @throws DSigException
	 */
	public TrustDelegation generateBootstrapTD(String custodianDN, X509Certificate[] issuer, String issuerName,
			String issuerFormat, PrivateKey pk, String receiverDN, DelegationRestrictions restrictions) 
		throws DSigException;
	
	
	/**
	 * Generates trust delegation in terms of certificates.
	 * @param custodian of initial trust delegation issuer (if not in trust delegation chain 
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
	 * As {@link #generateTD(X509Certificate, X509Certificate[], PrivateKey, X509Certificate[], DelegationRestrictions)}
	 * but additionally allows to add custom attributes to the assertion being generated.
	 * @since 3.1.0
	 * @param custodian
	 * @param issuer
	 * @param pk
	 * @param receiver
	 * @param restrictions
	 * @param attributes
	 * @return new trust delegation
	 * @throws DSigException
	 * @throws CertificateEncodingException
	 */
	public TrustDelegation generateTD(X509Certificate custodian, X509Certificate[] issuer, 
			PrivateKey pk, X509Certificate[] receiver, DelegationRestrictions restrictions,
			List<SAMLAttribute> attributes)	throws DSigException, CertificateEncodingException;	

	
	/**
	 * Validate single trust delegation assertion. Checks if receiver has trust of custodian 
	 * delegated by issuer. This validation is done in terms of DNs.
	 *  
	 * @param td
	 * @param custodian
	 * @param issuer
	 * @param receiver
 	 * @param validator certificate chain validator, used to check issuer cert chain.
	 * @return validation result
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
	 * @return validation result
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
	 * @param validator certificate chain validator, used to check all issuers certificates.
	 * @param trustedIssuers collection of certificates which are trusted as bootstrap delegation issuers (since U7)
	 * @return validation result
	 */
	public ValidationResult isTrustDelegated(List<TrustDelegation> td, String subject, 
			String user, X509CertChainValidator validator, 
			Collection<X509Certificate> trustedIssuers);

	/**
	 * Tests if the specified trust delegation chain delegates the trust from user to
	 * subject. Please note that if the subject is the receiver of the assertion that is not
	 * the last one in the chain, then the rest of the chain not need to be checked 
	 * (and can be theoretically invalid).
	 * This validation is done in terms of certificates.
	 * @param td
	 * @param subject
	 * @param user
	 * @param validator certificate chain validator, used to check all issuers certificates.
	 * @param trustedIssuers collection of certificates which are trusted as bootstrap delegation issuers (since U7)
	 * @return validation result
	 */
	public ValidationResult isTrustDelegated(List<TrustDelegation> td, X509Certificate[] subject, 
			X509Certificate[] user, X509CertChainValidator validator, 
			Collection<X509Certificate> trustedIssuers);
	
	/**
	 * Helper method to check if the subject is present in the chain. The chain is
	 * not checked for consistency, so it should be validated before.
	 * @return true if subject is present in chain
	 */
	public boolean isSubjectInChain(List<TrustDelegation> td, String subject);

}
