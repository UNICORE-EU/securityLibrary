/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 24, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.user;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;

import eu.unicore.saml.SAMLAssertion;
import eu.unicore.saml.SAMLParseException;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AttributeStatementType;
import xmlbeans.org.oasis.saml2.assertion.AttributeType;


/**
 * Java representation of user token. Usually client produces it and put into request header
 * to specify that request should be performed on the behalf of the user.
 * 
 * @author K. Benedyczak
 */
public class UserAssertion extends SAMLAssertion
{
	private static final long serialVersionUID = 7953888384523638747L;
	public static final String USER_ROLE = "USER";
	public static final String ROLE_NAME_FORMAT = "urn:unicore:subject-role";

	/**
	 * Creates user assertion with USER specified as DN
	 * @param consignorDN
	 * @param userDN
	 */
	public UserAssertion(String consignorDN, String userDN)
	{
		super("_userRole_");
		constructorCommon(consignorDN, userDN);
	}

	/**
	 * Creates user assertion with USER identity specified as full certificate chain
	 * (however you can use 1 element array to pass only single user's certificate 
	 * without CA's).
	 * @param consignorDN
	 * @param userCertChain
	 * @throws CertificateEncodingException
	 */
	public UserAssertion(String consignorDN, X509Certificate[] userCertChain) 
		throws CertificateEncodingException
	{
		super("_userRole_");
		String userDN = userCertChain[0].getSubjectX500Principal().getName();
		constructorCommon(consignorDN, userDN);
		setSenderVouchesX509Confirmation(userCertChain);
	}
	
	private void constructorCommon(String consignorDN, String userDN)
	{
		addAttribute(USER_ROLE, ROLE_NAME_FORMAT,
				new XmlObject[] {});
		setX509Issuer(consignorDN);
		setX509Subject(userDN);
	}
	
	public UserAssertion(AssertionDocument doc) 
		throws SAMLParseException, XmlException, IOException
	{
		super(doc);
		if (getSubject() == null)
			throw new SAMLParseException("No subject (user) in assertion.");
		boolean found = false;
		AttributeStatementType[] attrSs = getAttributes();
		if (attrSs == null)
			throw new SAMLParseException("No attribute statement in SAML assertion");
		for (int i=0; i<attrSs.length; i++)
		{
			AttributeType []attrs = attrSs[i].getAttributeArray();			
			for (int j=0; j<attrs.length; j++)
				if (attrs[j].getName().equals(USER_ROLE) && 
					attrs[j].getNameFormat().equals(ROLE_NAME_FORMAT))
				{
					found = true;
					break;
				}
			if (found)
				break;
		}
		if (!found)
			throw new SAMLParseException("SAML assertion doesn't contain user " +
					"role attirbute");
	}
	
	public String getUserDN()
	{
		return getSubject();
	}

	public X509Certificate[] getUserCertificate()
	{
		return getSubjectFromConfirmation();
	}
}
