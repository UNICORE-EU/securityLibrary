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
