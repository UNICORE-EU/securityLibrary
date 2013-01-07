/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.security.consignor;

import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.trust.SimpleTrustChecker;
import eu.unicore.samly2.validators.AssertionValidator;

/**
 * @author K. Benedyczak
 */
public class ConsignorValidator extends AssertionValidator
{
	private X509Certificate issuerCert;
	
	public ConsignorValidator(X509Certificate issuerCertificate)
	{
		super(null, null, null,	AssertionValidator.DEFAULT_VALIDITY_GRACE_PERIOD, 
				new SimpleTrustChecker(issuerCertificate, true));
		this.issuerCert = issuerCertificate;
	}
	
	
	public void validate(AssertionDocument assertionDoc) throws SAMLValidationException
	{
		super.validate(assertionDoc);
		AssertionType assertion = assertionDoc.getAssertion();
		if (assertion.getSubject().getNameID() == null || assertion.getSubject().getNameID().isNil())
			throw new SAMLValidationException("Assertion must have its Subject/NameID set");
		String format = assertion.getSubject().getNameID().getFormat();
		if (!SAMLConstants.NFORMAT_DN.equals(format))
			throw new SAMLValidationException("Assertion Subject must be of DN format");
		String formatI = assertion.getIssuer().getFormat();
		if (!SAMLConstants.NFORMAT_DN.equals(formatI))
			throw new SAMLValidationException("Assertion Issuer must be of DN format");
		X500Principal i2 = issuerCert.getSubjectX500Principal();
		if (!X500NameUtils.equal(i2, assertion.getIssuer().getStringValue()))
			throw new SAMLValidationException("Issuer of assertion is not equal to the expected one: " + 
					X500NameUtils.getReadableForm(assertion.getIssuer().getStringValue()));
	}
	
	@Override
	protected void checkStatements(AssertionType assertion) throws SAMLValidationException
	{
		//Consignor assertions are mixed
	}
}
