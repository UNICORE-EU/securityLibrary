/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 24, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.HexEncoder;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.samly2.exceptions.SAMLValidationException;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.assertion.AttributeStatementType;
import xmlbeans.org.oasis.saml2.assertion.AttributeType;
import xmlbeans.org.oasis.saml2.assertion.SubjectType;


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
	public static final String CUSTODIAN_NAME_FORMAT_SHA2 = "urn:unicore:trust-delegation:sha2hashcode";

	private String custodianDN;
	private Integer legacyHash;
	private String sha2Hash;
	
	public TrustDelegation(String custodian)
	{
		String dn = X500NameUtils.getPortableRFC2253Form(custodian);
		custodianDN = dn;
		legacyHash = null;
		sha2Hash = null;
		SAMLAttribute custodianA = new SAMLAttribute(CUSTODIAN_NAME, 
			CUSTODIAN_NAME_FORMAT_DN);
		custodianA.addStringAttributeValue(dn);
		addAttribute(custodianA);
	}

	public TrustDelegation(X509Certificate custodian)
	{
		this(custodian.getSubjectX500Principal().getName(),
				generateSha2Hash(custodian),
				custodian.hashCode());
	}

	public TrustDelegation(String custodianDN, String sha2Hash, Integer legacyHash)
	{
		this.custodianDN = custodianDN;
		SAMLAttribute custodianA = new SAMLAttribute(CUSTODIAN_NAME, 
			CUSTODIAN_NAME_FORMAT_DN);
		custodianA.addStringAttributeValue(custodianDN);
		addAttribute(custodianA);
		
		if (sha2Hash != null)
		{
			this.sha2Hash = sha2Hash;
			SAMLAttribute custodian2A = new SAMLAttribute(CUSTODIAN_NAME, 
					CUSTODIAN_NAME_FORMAT_SHA2);
			custodian2A.addStringAttributeValue(sha2Hash);
			addAttribute(custodian2A);
		}
		
		//legacy
		if (legacyHash != null)
		{
			this.legacyHash = legacyHash;
			SAMLAttribute custodian3A = new SAMLAttribute(CUSTODIAN_NAME, 
					CUSTODIAN_NAME_FORMAT_FP);
			custodian3A.addStringAttributeValue(legacyHash + "");
			addAttribute(custodian3A);
		}
	}
	
	public TrustDelegation(AssertionDocument doc) throws SAMLValidationException, XmlException, IOException
	{
		super(doc);
		AssertionType assertion = doc.getAssertion();
		SubjectType subject = assertion.getSubject();
		if (subject == null || subject.isNil() || subject.getNameID() == null || 
				subject.getNameID().isNil() || subject.getNameID().getStringValue() == null)
			throw new SAMLValidationException("No subject (user) in assertion.");
		AttributeStatementType[] attrSs = assertion.getAttributeStatementArray();
		custodianDN = null;
		if (attrSs == null)
			throw new SAMLValidationException("No attribute statement in SAML assertion");
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
					cur.dispose();
				} else if (attrs[j].getNameFormat().equals(CUSTODIAN_NAME_FORMAT_FP))
				{ //backwards compatibility - we support U6.x cert hashes, which are hashes of java objects
					XmlCursor cur = attrs[j].getAttributeValueArray(0)
						.newCursor();
					cur.toFirstContentToken();
					try
					{
						legacyHash = Integer.parseInt(cur.getTextValue());
					} catch (NumberFormatException e)
					{
						throw new SAMLValidationException(
							"Custodian certificate hash " +
							"value is not an integer");						
					}
					cur.dispose();
				} else if (attrs[j].getNameFormat().equals(CUSTODIAN_NAME_FORMAT_SHA2))
				{ //SHA2 hashes used from U7
					XmlCursor cur = attrs[j].getAttributeValueArray(0).newCursor();
					cur.toFirstContentToken();
					sha2Hash = cur.getTextValue();
					cur.dispose();
				}
			}
		}
		if (custodianDN == null)
			throw new SAMLValidationException("SAML assertion doesn't contain trust " +
					"delegation attribute");
	}
	
	public static String generateSha2Hash(X509Certificate custodian)
	{
		SHA256Digest digest = new SHA256Digest();
		byte[] binary;
		try
		{
			binary = custodian.getEncoded();
		} catch (CertificateEncodingException e1)
		{
			throw new RuntimeException("Shouldn't happen - can't get binary DER form of a certificate", e1);
		}
		digest.update(binary, 0, binary.length);
		byte[] result = new byte[digest.getByteLength()];
		digest.doFinal(result, 0);
		HexEncoder encoder = new HexEncoder();
		ByteArrayOutputStream baos = new ByteArrayOutputStream(); 
		try
		{
			encoder.encode(result, 0, result.length, baos);
		} catch (IOException e)
		{
			throw new RuntimeException("Shouldn't happen", e);
		}
		return baos.toString();
	}
	
	public String getCustodianDN()
	{
		return custodianDN;
	}
	
	public Integer getCustodianCertHash()
	{
		return legacyHash;
	}
	
	public String getCustodianCertHashSha2()
	{
		return sha2Hash;
	}
}
