/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.dsig;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.PublicKey;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import eu.unicore.security.TestBase;
import sun.security.rsa.RSAPublicKeyImpl;

/**
 * Tests generation and verification of enveloped signature.
 * @author K. Benedyczak
 */
public class DSigTest extends TestBase
{
	public void testSignVerify()
	{
		try
		{
			DigSignatureUtil dsigEngine = new DigSignatureUtil();
			Document doc = readDoc("/doc.xml");
			
			Node n = doc.getDocumentElement().getChildNodes().item(1);
			PublicKey pubKey = issuerCert1[0].getPublicKey();
			dsigEngine.genEnvelopedSignature(privKey1, pubKey, issuerCert1, 
				doc, n);

			assertTrue(dsigEngine.verifyEnvelopedSignature(doc, pubKey));
			
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}
	
	public void testVerify()
	{
		try
		{
			DigSignatureUtil dsigEngine = new DigSignatureUtil();
			Document doc = readDoc("/docSigned.xml");
			
			BigInteger modulus = new BigInteger("163777238822666015285329706279830595411974064586059702871587099431512157455719495774518770867278091194963281647181853106959836263061780091305987288645684760669758102471364248456086999347113921145640831970575719191169166816785623263506972893282383928337258596366986798122055894688767641149446988631156789299337");
			BigInteger expotent = new BigInteger("65537");
			PublicKey pubKey = new RSAPublicKeyImpl(modulus, expotent);

			boolean result = dsigEngine.verifyEnvelopedSignature(doc, pubKey);
			assertTrue(result);
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}
	
	private Document readDoc(String file) throws Exception
	{
		DocumentBuilderFactory builderFactory = 
			DocumentBuilderFactory.newInstance();
		builderFactory.setNamespaceAware(true);
		DocumentBuilder docBuilder = builderFactory.newDocumentBuilder();
		InputStream is = getClass().getResourceAsStream(file);
		return docBuilder.parse(is);
	}
}
