/*********************************************************************************
 * Copyright (c) 2006-2008 Forschungszentrum Juelich GmbH 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * (1) Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the disclaimer at the end. Redistributions in
 * binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * 
 * (2) Neither the name of Forschungszentrum Juelich GmbH nor the names of its 
 * contributors may be used to endorse or promote products derived from this 
 * software without specific prior written permission.
 * 
 * DISCLAIMER
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ********************************************************************************/

package eu.unicore.security.canl;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

import org.apache.logging.log4j.Logger;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.FormatMode;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.util.Log;

/**
 * This class is decorating a wrapped trust manager with optional logging
 * on DEBUG level of certificates. It is a convenient way to log all (including failed)
 * connections.
 * <p>
 * The class adds a very short (20ms) grace period before sending an error, when client's certificate is not
 * valid. This should minimize the chance of getting broken pipe error on client's side.
 */
public class LoggingX509TrustManager extends X509ExtendedTrustManager {

	private static final Logger log = Log.getLogger(Log.SECURITY, LoggingX509TrustManager.class);

	private final X509ExtendedTrustManager defaultTrustManager;
	private final String info;

	public LoggingX509TrustManager(final X509ExtendedTrustManager defaultTrustManager, String info) {
		if (defaultTrustManager == null) {
			throw new IllegalArgumentException("Trust manager may not be null");
		}
		this.info = info;
		this.defaultTrustManager = defaultTrustManager;
	}
	
	@Override
	public void checkClientTrusted(X509Certificate[] certificates, String s)
			throws CertificateException {
		wrapClientCertCheck(certificates, () -> defaultTrustManager.checkClientTrusted(certificates, s));
	}

	@Override
	public void checkServerTrusted(X509Certificate[] certificates, String s)
			throws CertificateException {
		wrapServerCertCheck(certificates, () -> defaultTrustManager.checkServerTrusted(certificates, s));
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
			throws CertificateException
	{
		wrapClientCertCheck(chain, () -> defaultTrustManager.checkClientTrusted(chain, authType, socket));
	}


	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
			throws CertificateException
	{
		wrapServerCertCheck(chain, () -> defaultTrustManager.checkServerTrusted(chain, authType, socket));
	}


	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
			throws CertificateException
	{
		wrapClientCertCheck(chain, () -> defaultTrustManager.checkClientTrusted(chain, authType, engine));
	}


	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
			throws CertificateException
	{
		wrapServerCertCheck(chain, () -> defaultTrustManager.checkServerTrusted(chain, authType, engine));
	}
	
	private void wrapServerCertCheck(X509Certificate[] chain, CertChecker checker)
			throws CertificateException
	{
		logCerts("Checking server's certificate:\n", chain);
		try
		{
			checker.check();
			logSuccessfulVerification("server", chain);			
		} catch (CertificateException e)
		{
			//let's wait so client has bigger chance to finish its sending of handshake material
			//the 20ms is a quite random guess... 
			try
			{
				Thread.sleep(20);
			} catch (InterruptedException e1) { /*ignored*/ }
			logFailedVerification("server", e);
			throw e;
		}
	}

	private void wrapClientCertCheck(X509Certificate[] chain, CertChecker checker)
			throws CertificateException
	{
		logCerts("Checking client's certificate:\n", chain);
		try
		{
			checker.check();
			logSuccessfulVerification("client", chain);			
		} catch (CertificateException e)
		{
			logFailedVerification("client", e);
			throw e;
		}
	}

	
	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return defaultTrustManager.getAcceptedIssuers();
	}
	
	private void logCerts(String type, X509Certificate[] certificates)
	{
		if (log.isDebugEnabled() && certificates != null) {
			String info = CertificateUtils.format(certificates, FormatMode.FULL);
			log.debug("[" + this.info + "] " + type + info);
		}
	}
	
	private void logFailedVerification(String type, CertificateException e) {
		if (!log.isDebugEnabled())
			return;
		log.debug("[" + info + "] Verification of the " + type + " certificate failed. " + 
			e.getMessage());
	}

	private void logSuccessfulVerification(String type, X509Certificate[] certificates) {
		if (!log.isDebugEnabled())
			return;
		log.debug("[" + info + "] Verification of the " + type + 
			" certificate with subject DN " + 
			X500NameUtils.getReadableForm(certificates[0].getSubjectX500Principal())
			+ " was successful");
	}

	private interface CertChecker
	{
		void check() throws CertificateException;
	}
}
