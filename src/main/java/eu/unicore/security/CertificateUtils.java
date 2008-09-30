/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 2008-09-26
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * Verifies if the certificate is not expired. In future CRL support
 * should be added here. 
 * <p>
 * This class is used internally by other APIs. Every certificate which is used
 * at any <b>validation</b> (e.g. check if ETD assertion is valid) is checked. 
 * By default certificates used in any <b>generation</b> (e.g. creation of Consignor token)
 * is not checked. You can change this behaviour by setting
 * VERIFY_GENERATION_KEY property to "true".
 * 
 * TODO implement CRL support.
 * @author golbi
 */
public class CertificateUtils
{
	public static final String VERIFY_GENERATION_KEY = 
		"eu.unicore.securty.VerifyExpiredCertUponCreation";
	
	public static void verifyCertificate(X509Certificate cert, boolean doCRLCheck, 
		boolean isGenerateMode) 
		throws CertificateExpiredException, CertificateNotYetValidException
	{
		String verify = System.getProperty(CertificateUtils.VERIFY_GENERATION_KEY); 
		if (!isGenerateMode || (verify != null && verify.equals("true")))
			cert.checkValidity();
	}

	public static void verifyCertificate(X509Certificate[] certs, boolean doCRLCheck,
		boolean isGenerateMode) 
		throws CertificateExpiredException, CertificateNotYetValidException
	{
		for (X509Certificate cert: certs)
			verifyCertificate(cert, doCRLCheck, isGenerateMode);
	}

	
}
