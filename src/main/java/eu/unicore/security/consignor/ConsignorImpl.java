/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 7, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.consignor;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import xmlbeans.org.oasis.saml2.assertion.AuthnContextDocument;
import xmlbeans.org.oasis.saml2.assertion.SubjectLocalityDocument;
import xmlbeans.org.oasis.saml2.assertion.SubjectLocalityType;

import eu.unicore.samly2.SAMLConstants.AuthNClasses;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.security.Client;
import eu.unicore.security.ValidationResult;
import eu.unicore.security.dsig.DSigException;

/**
 * Implements logic to generate and validate consignor tokens.
 * <p>
 * @author K. Benedyczak
 */
public class ConsignorImpl implements ConsignorAPI
{
	/**
	 * @see eu.unicore.security.consignor.ConsignorAPI#generateConsignorToken(java.lang.String, java.security.cert.X509Certificate, java.security.PrivateKey, eu.unicore.saml.SAMLConstants.AuthNClasses)
	 */
	public ConsignorAssertion generateConsignorToken(String issuerDN, 
			X509Certificate []consignorCert, PrivateKey pk, int negativeTolerance,
			int validity, AuthNClasses acClass, String ip) 
		throws DSigException
	{
		ConsignorAssertion assertion = new ConsignorAssertion();
		assertion.setX509Issuer(issuerDN);
		if (consignorCert != null)
		{
			assertion.setX509Subject(
				consignorCert[0].getSubjectX500Principal().getName());
			try
			{
				assertion.setSenderVouchesX509Confirmation(consignorCert);
			} catch (CertificateEncodingException e)
			{
				throw new DSigException(e);
			}
		} else
		{
			assertion.setX509Subject(Client.ANONYMOUS_CLIENT_DN);
		}
		Calendar cur = Calendar.getInstance();
		if (acClass.equals(AuthNClasses.TLS))
		{
			AuthnContextDocument dummyCtx = AuthnContextDocument.Factory.newInstance();
			SubjectLocalityDocument locDoc = SubjectLocalityDocument.Factory.newInstance();
			SubjectLocalityType loc = locDoc.addNewSubjectLocality();
			loc.setAddress(ip);
			assertion.addAuthStatement(cur, dummyCtx.addNewAuthnContext(), null, null, loc);
		}
		Date notBefore = null;
		Date notOnOrAfter = null;
		if (negativeTolerance >= 0)
		{
			cur.add(Calendar.SECOND, -negativeTolerance);
			notBefore = cur.getTime();
		}
		if (validity >= 0)
		{
			cur.add(Calendar.SECOND, validity);
			notOnOrAfter = cur.getTime();
		}
		if (notBefore != null || notOnOrAfter != null)
			assertion.setTimeConditions(notBefore, notOnOrAfter);
		
		
		if (pk != null)
			assertion.sign(pk);
		return assertion;
	}
	
	/**
	 * @see eu.unicore.security.consignor.ConsignorAPI#verifyConsignorToken(eu.unicore.security.consignor.ConsignorAssertion, java.security.cert.X509Certificate)
	 */
	public ValidationResult verifyConsignorToken(ConsignorAssertion assertion,
			X509Certificate issuerCertificate)
	{
		ConsignorValidator validator = new ConsignorValidator(issuerCertificate);
		try
		{
			validator.validate(assertion.getXMLBeanDoc());
		} catch (SAMLValidationException e)
		{
			return new ValidationResult(false, e.getMessage());
		}
		return new ValidationResult(true, "OK");
	}

	public ConsignorAssertion generateConsignorToken(String issuerDN, 
			X509Certificate []consignorCert, AuthNClasses acClass, String ip) 
		throws DSigException
	{
		return generateConsignorToken(issuerDN, consignorCert, null, 
					-1, -1, acClass, ip);
	}

	public ConsignorAssertion generateConsignorToken(String issuerDN, 
			int negativeTolerance, int validity, PrivateKey pk, String ip) 
		throws DSigException
	{
		return generateConsignorToken(issuerDN, null, pk, negativeTolerance,
				validity, AuthNClasses.NONE, ip);
	}

	public ConsignorAssertion generateConsignorToken(String issuerDN)
	{
		try
		{
			return generateConsignorToken(issuerDN, null, null, 
					-1, -1, AuthNClasses.NONE, null);
		} catch (DSigException e)
		{
			// can't happen
			return null;
		}
	}
}
