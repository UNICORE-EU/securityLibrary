/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 2008-09-26
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import eu.unicore.crlcheck.CRLCheckResult;
import eu.unicore.crlcheck.CRLManager;
import eu.unicore.crlcheck.CRLManagerProperties;

/**
 * Verifies if the certificate is not expired or revoked (if CRL check is configured)
 * Also, additional certificate handling utils are provided. 
 * <p>
 * This class is used internally by other APIs. Every certificate which is used
 * at any <b>validation</b> (e.g. check if ETD assertion is valid) is checked. 
 * By default certificates used in any <b>generation</b> (e.g. creation of Consignor token)
 * is not checked. You can change this behavior by setting
 * VERIFY_GENERATION_KEY property to "true".
 * 
 * @author golbi
 */
public class CertificateUtils
{

	public static final String VERIFY_GENERATION_KEY = "eu.unicore.securty.VerifyExpiredCertUponCreation";
	public static final String CRLMGR_PROPS_FILE     = "crlmanager.properties.file";

	private static CRLManager crlManager = null;

	static {
		String crlManagerPropertiesFile=System.getProperty(CRLMGR_PROPS_FILE);
		if(crlManagerPropertiesFile!=null){
			CRLManagerProperties crlMgrProps = new CRLManagerProperties();
			FileInputStream fis=null;
			try
			{
				fis=new FileInputStream(crlManagerPropertiesFile);
				crlMgrProps.load(fis);
			}
			catch (Exception e)
			{
				System.err.println("Error initialising CRL checker.");
				e.printStackTrace();
			}
			finally{
				if(fis!=null)try{fis.close();}catch(IOException ignored){}
			}
			crlManager=new CRLManager(crlMgrProps);
		}

	}

	public static void verifyCertificate(X509Certificate cert, boolean doCRLCheck, boolean isGenerateMode) throws CertificateExpiredException, CertificateNotYetValidException
	{
		String verify = System.getProperty(CertificateUtils.VERIFY_GENERATION_KEY);
		if (!isGenerateMode || (verify != null && verify.equals("true"))) cert.checkValidity();

		if (doCRLCheck && crlManager!=null)
		{
			CRLCheckResult cr = crlManager.checkCertificate(cert);
			if (!cr.isValid())
			{
				// TODO Is there a better exception for this?
				throw new CertificateExpiredException("CRL check failed: "+cr.getReason());
			}
		}
	}

	public static void verifyCertificate(X509Certificate[] certs, boolean doCRLCheck, boolean isGenerateMode) throws CertificateExpiredException, CertificateNotYetValidException
	{
		for (X509Certificate cert : certs)
			verifyCertificate(cert, doCRLCheck, isGenerateMode);
	}

	public static String safePrintSubject(X509Certificate cert)
	{
		if (cert == null) return "EMPTY certificate";
		if (cert.getSubjectX500Principal() == null) return "certificate without a subject";
		return cert.getSubjectX500Principal().getName();
	}

	public static String safePrintSubject(X509Certificate[] cert)
	{
		if (cert == null || cert.length == 0) return "EMPTY certificate";
		return safePrintSubject(cert[0]);
	}
}
