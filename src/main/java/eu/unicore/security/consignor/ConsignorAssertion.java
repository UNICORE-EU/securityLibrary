/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 24, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.consignor;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;

import eu.unicore.saml.SAMLAssertion;
import eu.unicore.saml.SAMLParseException;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AttributeStatementType;
import xmlbeans.org.oasis.saml2.assertion.AttributeType;


/**
 * Java representation of gateway produced consignor token. Usually gateway produces it
 * form TLS certificate, sign with own private key and attach to request before forwarding it to 
 * target system. 
 * <p>Note that those tokens can be cached to improve performance.
 * @author K. Benedyczak
 */
public class ConsignorAssertion extends SAMLAssertion
{
	private static final long serialVersionUID = 9087483370558929619L;
	public static final String CONSIGNOR_ROLE = "CONSIGNOR";
	public static final String ROLE_NAME_FORMAT = "urn:unicore:subject-role";

	
	public ConsignorAssertion()
	{
		super("_consignorRole_");
		addAttribute(CONSIGNOR_ROLE, ROLE_NAME_FORMAT, 
				new XmlObject[] {});
	}
	
	public ConsignorAssertion(AssertionDocument doc) 
		throws SAMLParseException, XmlException, IOException
	{
		super(doc);
		//BUGFIX - it is ok to get Consignor assertion with no subject
		//it means that Gateway processed the request but requester was not authenticated.
		//if (getSubject() == null)
		//	throw new SAMLParseException("No subject (consignor) in assertion.");
		boolean found = false;
		AttributeStatementType[] attrSs = getAttributes();
		if (attrSs == null)
			throw new SAMLParseException("No attribute statement in SAML assertion");
		for (int i=0; i<attrSs.length; i++)
		{
			AttributeType []attrs = attrSs[i].getAttributeArray();			
			for (int j=0; j<attrs.length; j++)
				if (attrs[j].getName().equals(CONSIGNOR_ROLE) && 
					attrs[j].getNameFormat().equals(ROLE_NAME_FORMAT))
				{
					found = true;
					break;
				}
			if (found)
				break;
		}
		if (!found)
			throw new SAMLParseException("SAML assertion doesn't contain consignor role " +
					"attirbute");
	}
	
	public X509Certificate[] getConsignor()
	{
		return getSubjectFromConfirmation();
	}
}
