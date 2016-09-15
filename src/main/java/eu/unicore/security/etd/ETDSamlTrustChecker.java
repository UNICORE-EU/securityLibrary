/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.etd;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.w3.x2000.x09.xmldsig.SignatureType;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.trust.CheckingMode;
import eu.unicore.samly2.trust.DsigSamlTrustCheckerBase;
import eu.unicore.samly2.trust.SamlTrustChecker;

/**
 * This implementation of {@link SamlTrustChecker} checks if the signature is correct,
 * and if the issuer certificate is trusted as decided by a {@link X509CertChainValidator}.
 * <p>
 * NOTE: this class is NOT useful for typical SAML situations, where trusted issuers are 
 * few, selected and configured one by one entities. It is useful mostly for ETD.
 * 
 * @author K. Benedyczak
 */
public class ETDSamlTrustChecker extends DsigSamlTrustCheckerBase
{
	protected X509CertChainValidator validator;
	protected X509Certificate[] expectedIssuer;
	
	public ETDSamlTrustChecker(X509CertChainValidator validator, X509Certificate[] expectedIssuer)
	{
		super(CheckingMode.REQUIRE_SIGNED_ASSERTION);
		this.validator = validator;
		this.expectedIssuer = expectedIssuer;
	}

	@Override
	protected PublicKey establishKey(NameIDType issuer, SignatureType signature)
			throws SAMLValidationException
	{
		ValidationResult result = validator.validate(expectedIssuer);
		if (!result.isValid())
		{
			throw new SAMLValidationException("Delegation signature was conducted by an untrusted entity: " 
					+ result.toShortString());
		}
		return expectedIssuer[0].getPublicKey();
	}

}
