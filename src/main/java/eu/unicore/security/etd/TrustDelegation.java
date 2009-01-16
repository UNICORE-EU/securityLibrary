/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 24, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.apache.xml.security.utils.RFC2253Parser;
import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlException;

import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.samly2.exceptions.SAMLParseException;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AttributeStatementType;
import xmlbeans.org.oasis.saml2.assertion.AttributeType;


/**
 * Java representation of trust delegation token.
 * @author K. Benedyczak
 */
public class TrustDelegation extends Assertion
{

	private static final long serialVersionUID = 1L;

	public static final String CUSTODIAN_NAME = "TrustDelegationOfUser";
	public static final String CUSTODIAN_NAME_FORMAT_DN = "urn:unicore:trust-delegation:dn";
	public static final String CUSTODIAN_NAME_FORMAT_FP = "urn:unicore:trust-delegation:hashcode";

	private String custodianDN;
	private Integer hash;
	
	public TrustDelegation(String custodian)
	{
		super();
		String dn = RFC2253Parser.rfc2253toXMLdsig(custodian);
		custodianDN = dn;
		hash = null;
		SAMLAttribute custodianA = new SAMLAttribute(CUSTODIAN_NAME, 
			CUSTODIAN_NAME_FORMAT_DN);
		custodianA.addStringAttributeValue(dn);
		addAttribute(custodianA);
	}

	public TrustDelegation(X509Certificate custodian)
	{
		super();
		
		String dn = RFC2253Parser.rfc2253toXMLdsig(
				custodian.getSubjectX500Principal().getName());
		custodianDN = dn;
		SAMLAttribute custodianA = new SAMLAttribute(CUSTODIAN_NAME, 
			CUSTODIAN_NAME_FORMAT_DN);
		custodianA.addStringAttributeValue(dn);
		addAttribute(custodianA);
		hash = custodian.hashCode();
		
		SAMLAttribute custodian2A = new SAMLAttribute(CUSTODIAN_NAME, 
			CUSTODIAN_NAME_FORMAT_FP);
		custodian2A.addStringAttributeValue(hash + "");
		addAttribute(custodian2A);
	}
	
	public TrustDelegation(AssertionDocument doc) throws SAMLParseException, XmlException, IOException
	{
		super(doc);
		if (getSubjectDN() == null)
			throw new SAMLParseException("No subject (user) in assertion.");
		AttributeStatementType[] attrSs = getAttributes();
		custodianDN = null;
		if (attrSs == null)
			throw new SAMLParseException("No attribute statement in SAML assertion");
		for (int i=0; i<attrSs.length; i++)
		{
			AttributeType []attrs = attrSs[i].getAttributeArray();			
			for (int j=0; j<attrs.length; j++)
			{
				if (!attrs[j].getName().equals(CUSTODIAN_NAME))
					continue;
				if (attrs[j].getNameFormat().equals(CUSTODIAN_NAME_FORMAT_DN))
				{
					XmlCursor cur = attrs[j].getAttributeValueArray(0)
						.newCursor();
					cur.toFirstContentToken();
					custodianDN = cur.getTextValue();
				} else if (attrs[j].getNameFormat().equals(CUSTODIAN_NAME_FORMAT_FP))
				{
					XmlCursor cur = attrs[j].getAttributeValueArray(0)
						.newCursor();
					cur.toFirstContentToken();
					try
					{
						hash = Integer.parseInt(cur.getTextValue());
					} catch (NumberFormatException e)
					{
						throw new SAMLParseException(
							"Custodian certificate hash " +
							"value is not an integer");						
					}
				}
			}
		}
		if (custodianDN == null)
			throw new SAMLParseException("SAML assertion doesn't contain trust " +
					"delegation attribute");
	}
	
	public String getCustodianDN()
	{
		return custodianDN;
	}
	
	public Integer getCustodianCertHash()
	{
		return hash;
	}
	
}
