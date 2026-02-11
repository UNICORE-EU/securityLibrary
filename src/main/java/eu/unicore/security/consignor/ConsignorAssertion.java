package eu.unicore.security.consignor;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.apache.xmlbeans.XmlException;

import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.samly2.assertion.AssertionParser;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.samly2.exceptions.SAMLValidationException;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AttributeStatementType;
import xmlbeans.org.oasis.saml2.assertion.AttributeType;


/**
 * Java representation of gateway produced consignor token. Usually gateway produces it
 * form TLS certificate, sign with own private key and attach to request before forwarding it to 
 * target system. 
 * @author K. Benedyczak
 */
public class ConsignorAssertion extends Assertion
{
	private static final long serialVersionUID = 9087483370558929619L;
	public static final String CONSIGNOR_ROLE = "CONSIGNOR";
	public static final String ROLE_NAME_FORMAT = "urn:unicore:subject-role";

	public ConsignorAssertion()
	{
		super();
		SAMLAttribute attribute = new SAMLAttribute(CONSIGNOR_ROLE, ROLE_NAME_FORMAT);
		addAttribute(attribute);
	}
	
	public ConsignorAssertion(AssertionDocument doc) 
		throws SAMLValidationException, XmlException, IOException
	{
		//BUGFIX - it is ok to get Consignor assertion with no subject
		//it means that Gateway processed the request but requester was not authenticated.
		//if (getSubject() == null)
		//	throw new SAMLParseException("No subject (consignor) in assertion.");
		boolean found = false;
		AttributeStatementType[] attrSs = doc.getAssertion().getAttributeStatementArray();
		if (attrSs == null)
			throw new SAMLValidationException("No attribute statement in SAML assertion");
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
			throw new SAMLValidationException("SAML assertion doesn't contain consignor role " +
					"attribute");

		this.assertionDoc = doc;
	}
	
	public X509Certificate[] getConsignor()
	{
		AssertionParser parser = new AssertionParser(getXMLBeanDoc());
		return parser.getSubjectFromConfirmation();
	}
}
