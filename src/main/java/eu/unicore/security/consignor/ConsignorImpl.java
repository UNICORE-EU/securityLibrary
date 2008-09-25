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

import org.apache.xml.security.utils.RFC2253Parser;

import eu.unicore.saml.SAMLConstants.AuthNClasses;
import eu.unicore.security.ValidationResult;
import eu.unicore.security.dsig.DSigException;

/**
 * Implements logic to generate and validate consignor tokens.
 * <p>
 * TODO: add (optional) AuthN context setting (mostly in underlaying SAMLAssertion) 
 * @author K. Benedyczak
 */
public class ConsignorImpl implements ConsignorAPI
{
	/**
	 * @see eu.unicore.security.consignor.ConsignorAPI#generateConsignorToken(java.lang.String, java.security.cert.X509Certificate, java.security.PrivateKey, eu.unicore.saml.SAMLConstants.AuthNClasses)
	 */
	public ConsignorAssertion generateConsignorToken(String issuerDN, 
			X509Certificate []consignorCert, PrivateKey pk, int negativeTolerance,
			int validity, AuthNClasses acClass) 
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
		}
		if (!acClass.equals(AuthNClasses.NONE))
		{
			if (acClass.equals(AuthNClasses.TLS))
			{
				
			}
		}
		Date notBefore = null;
		Date notOnOrAfter = null;
		if (negativeTolerance >= 0)
		{
			Calendar cur = Calendar.getInstance();
			cur.add(Calendar.SECOND, -negativeTolerance);
			notBefore = cur.getTime();
		}
		if (validity >= 0)
		{
			Calendar cur = Calendar.getInstance();
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
		String i1 = assertion.getIssuer();
		String i2 = RFC2253Parser.rfc2253toXMLdsig(
				issuerCertificate.getSubjectX500Principal().getName());
		if (!i1.equals(i2))
			return new ValidationResult(false, "Wrong issuer");
		if (!assertion.checkTimeConditions())
			return new ValidationResult(false, "Lifetime conditions are not met");
		try
		{
			if (assertion.isSigned() &&
					!assertion.isCorrectlySigned(
					issuerCertificate.getPublicKey()))
				return new ValidationResult(false, "Signature is invalid");
		} catch (DSigException e)
		{
			return new ValidationResult(false, e.getMessage());
		}
		return new ValidationResult(true, "OK");
	}

	public ConsignorAssertion generateConsignorToken(String issuerDN, 
			X509Certificate []consignorCert, AuthNClasses acClass)
	{
		try
		{
			return generateConsignorToken(issuerDN, consignorCert, null, 
					-1, -1, acClass);
		} catch (DSigException e)
		{
			//can't happen
			return null;
		}
	}

	public ConsignorAssertion generateConsignorToken(String issuerDN, 
			int negativeTolerance, int validity, PrivateKey pk) 
		throws DSigException
	{
		return generateConsignorToken(issuerDN, null, pk, negativeTolerance,
				validity, AuthNClasses.NONE);
	}

	public ConsignorAssertion generateConsignorToken(String issuerDN)
	{
		try
		{
			return generateConsignorToken(issuerDN, null, null, 
					-1, -1, AuthNClasses.NONE);
		} catch (DSigException e)
		{
			// can't happen
			return null;
		}
	}
}
