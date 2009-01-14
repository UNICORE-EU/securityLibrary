/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 24, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.dsig;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.apache.log4j.Logger;
import org.apache.xml.security.utils.Base64;
import org.apache.xmlbeans.XmlBase64Binary;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.unicore.security.CertificateUtils;

import xmlbeans.org.w3.x2000.x09.xmldsig.KeyInfoType;
import xmlbeans.org.w3.x2000.x09.xmldsig.X509DataType;


/**
 * Provides high-level API for signing and verifying XML signatures.
 * Only implements those kind of signatures that are relevant for
 * UNICORE security infractructure.
 * @author K. Benedyczak
 */
public class DigSignatureUtil
{
	private static final Logger log = Logger.getLogger("unicore.security.dsig." + 
		DigSignatureUtil.class.getSimpleName());
	private final static String PROVIDER = "refactored.org.jcp.xml.dsig.internal.dom.XMLDSigRI";
	private static XMLSignatureFactory fac = null;
	
	public DigSignatureUtil() throws DSigException
	{
		try
		{
			fac = XMLSignatureFactory.getInstance("DOM",
					(Provider) Class.forName(PROVIDER).newInstance());
		} catch (Exception e)
		{
			throw new DSigException("Initialization of digital signature " +
					"engine failed", e);
		}
	}
	
	public void genEnvelopedSignature(PrivateKey privKey, PublicKey pubKey, 
			X509Certificate []cert, Document docToSign, Node insertBefore) 
		throws DSigException
	{
		try
		{
			genEnvelopedSignatureInternal(privKey, pubKey, cert, docToSign, insertBefore);
		} catch (Exception e)
		{
			throw new DSigException("Creation of enveloped signature " +
					"failed", e);
		}
	}
	
	private void genEnvelopedSignatureInternal(PrivateKey privKey, PublicKey pubKey,  
			X509Certificate []cert, Document docToSign, Node insertBefore) 
		throws MarshalException, XMLSignatureException,	NoSuchAlgorithmException, 
		InvalidAlgorithmParameterException, KeyException, CertificateExpiredException, CertificateNotYetValidException
	{
		DigestMethod digistMethod = fac.newDigestMethod(DigestMethod.SHA1, null);
		Vector<Transform> transforms = new Vector<Transform>(); 

		if (cert != null)
			CertificateUtils.verifyCertificate(cert, false, true);

		
		transforms.add(fac.newTransform(Transform.ENVELOPED, 
				(TransformParameterSpec) null));
		transforms.add(fac.newTransform(CanonicalizationMethod.EXCLUSIVE, 
			(TransformParameterSpec) null));
		CanonicalizationMethod canMethod = fac.newCanonicalizationMethod(
				CanonicalizationMethod.EXCLUSIVE,
				(C14NMethodParameterSpec) null);
		
		SignatureMethod sigMethod;
		if (privKey instanceof RSAPrivateKey)
			sigMethod = fac.newSignatureMethod(
				SignatureMethod.RSA_SHA1, null);
		else if (privKey instanceof DSAPrivateKey)
			sigMethod = fac.newSignatureMethod(
				SignatureMethod.DSA_SHA1, null);
		else
			throw new KeyException("Unsupported private key algorithm " +
				"(must be DSA or RSA) :" + privKey.getAlgorithm());

		NamedNodeMap attrs = docToSign.getDocumentElement().getAttributes();
		Node idNode = attrs.getNamedItem("ID");
		String id = null;
		if (idNode != null)
			id = "#" + idNode.getNodeValue();
		
		Reference ref = fac.newReference(id, 
					digistMethod,
					transforms,
					null, null);
		SignedInfo si = fac.newSignedInfo(canMethod, sigMethod,
					Collections.singletonList(ref));

		DOMSignContext dsc = null;
		if (insertBefore == null)
			dsc = new DOMSignContext(privKey, 
				docToSign.getDocumentElement());
		else
			dsc = new DOMSignContext(privKey, 
					docToSign.getDocumentElement(), insertBefore);
		//hack to overcome gateway/ActiveSOAP bugs with default prefixes...
		dsc.putNamespacePrefix(
			"http://www.w3.org/2000/09/xmldsig#", 
			"dsig");
		KeyInfo ki = null;
		KeyInfoFactory kif = fac.getKeyInfoFactory();
		Vector<Object> kiVals = new Vector<Object>();
		if (pubKey != null)
		{
			KeyValue kv = kif.newKeyValue(pubKey);
			kiVals.add(kv);
		}
		if (cert != null)
		{
			ArrayList<X509Certificate> certList = 
				new ArrayList<X509Certificate>();
			for (X509Certificate c: cert)
				certList.add(c);
			X509Data x509Data = kif.newX509Data(certList);
			kiVals.add(x509Data);
		}
		if (kiVals.size() > 0)
			ki = kif.newKeyInfo(kiVals);
		
		XMLSignature signature = fac.newXMLSignature(si, ki);

		signature.sign(dsc);
	}
	
	public boolean verifyEnvelopedSignature(Document signedDocument, PublicKey validatingKey) 
		throws DSigException
	{
		try
		{
			return verifyEnvelopedSignatureInternal(signedDocument, validatingKey);
		} catch (Exception e)
		{
			throw new DSigException("Verification of enveloped signature " +
					"failed", e);
		}
	}	
	
	private boolean verifyEnvelopedSignatureInternal(Document signedDocument, 
			PublicKey validatingKey) 
		throws MarshalException, XMLSignatureException
	{
		NodeList nl = signedDocument.getElementsByTagNameNS(
				XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0)
			throw new XMLSignatureException("Document not signed");

		return verifySignatureInternal(signedDocument, validatingKey, nl.item(0));
	}

	public boolean verifyDetachedSignature(Document signedDocument, PublicKey validatingKey,
			Node signatureNode) 
		throws DSigException
	{
		try
		{
			return verifySignatureInternal(signedDocument, validatingKey, 
					signatureNode);
		} catch (Exception e)
		{
			throw new DSigException("Verification of detached signature " +
					"failed", e);
		}
	}	


	private boolean verifySignatureInternal(Document signedDocument, 
			PublicKey validatingKey, Node signatureNode) 
		throws MarshalException, XMLSignatureException
	{
		DOMValidateContext valContext = new DOMValidateContext(validatingKey,
				signatureNode);

		XMLSignature signature = fac.unmarshalXMLSignature(valContext);
		boolean coreValidity = signature.validate(valContext);

		if (coreValidity == false) 
			log.debug("Signature failed core validation");
		if (coreValidity == false && log.isTraceEnabled()) 
		{		
			boolean sv = signature.getSignatureValue().validate(valContext);
			log.debug("signature validation status: " + sv);
			Iterator i = signature.getSignedInfo().getReferences().iterator();
			for (int j=0; i.hasNext(); j++) 
			{
				Reference ref = (Reference) i.next(); 
				boolean refValid = ref.validate(valContext);

				log.trace("ref["+j+"] validity status: " + refValid);
				String s = new String(Base64.encode(ref.getDigestValue()));
				log.trace("ref["+j+"] digest: " + s);
				s = new String(Base64.encode(ref.getCalculatedDigestValue()));
				log.trace("ref["+j+"] calculated digest: " + s);
			}
		} 
		return coreValidity;
	}

	
	public static KeyInfoType generateX509KeyInfo(X509Certificate[] certs) 
		throws CertificateEncodingException
	{
		KeyInfoType ret = KeyInfoType.Factory.newInstance();
		X509DataType x509Data = ret.addNewX509Data();
		for (X509Certificate cert: certs)
		{
			XmlBase64Binary binCert = x509Data.addNewX509Certificate();
			byte []certRaw = cert.getEncoded();
			binCert.setByteArrayValue(certRaw);
		}
		return ret;
	}
	
	public List getReferencesFromSignature(Node signatureNode) 
		throws DSigException
	{
		DOMStructure xml = new DOMStructure(signatureNode);
		XMLSignature signature;
		try
		{
			signature = fac.unmarshalXMLSignature(xml);
		} catch (MarshalException e)
		{
			throw new DSigException("Can't unmarshal signature", e);
		}
		return signature.getSignedInfo().getReferences();
	}
}
