package eu.unicore.security.canl;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.Logger;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.FormatMode;
import eu.emi.security.authn.x509.impl.HostnameMismatchCallback2;
import eu.emi.security.authn.x509.impl.SocketFactoryCreator2;
import eu.unicore.util.httpclient.HostnameMismatchCallbackImpl;
import eu.unicore.util.httpclient.NoAuthKeyManager;
import eu.unicore.util.httpclient.ServerHostnameCheckingMode;

/**
 * This class should be used to create {@link SSLContext} or {@link SSLSocketFactory} in the "UNICORE
 * way". The context is created with key and trust managers using canl, decorated with UNICORE specific logging.
 * 
 * @author K. Benedyczak
 */
public class SSLContextCreator
{
	/**
	 * Creates SSLContext.
	 * @param credential if null then SSLContext won't be able to authenticate itself. Useful for anonymous SSL clients.
	 * @param validator required
	 * @param protocol protocol to be used, e.g. "TLS".
	 * @param loginfo message which will be used on TRACE level to identify the component
	 * @param log logger, used on TRACE level to dump some extra information
	 * @return SSLContext
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyManagementException 
	 */
	public static SSLContext createSSLContext(X509Credential credential, 
			X509CertChainValidator validator, String protocol, String loginfo, Logger log, 
			ServerHostnameCheckingMode hostnameCheckingMode) 
					throws NoSuchAlgorithmException, KeyManagementException
	{
		KeyManager km;
		if (credential != null)
		{
			km = credential.getKeyManager();
			if (log.isTraceEnabled())
				debugKS(credential, loginfo, log);
		} else
		{
			km = new NoAuthKeyManager();
			log.trace("Creating SSL context without client's certificate for " + loginfo);
		}

		HostnameMismatchCallback2 hostnameVerificationCallback = new HostnameMismatchCallbackImpl(hostnameCheckingMode);
		X509ExtendedTrustManager baseTM = (X509ExtendedTrustManager) new SocketFactoryCreator2(
				validator, hostnameVerificationCallback).getSSLTrustManager();
		X509TrustManager tm = new LoggingX509TrustManager(baseTM, loginfo);
		if (log.isTraceEnabled())
			debugTS(validator, loginfo, log);

		SSLContext sslcontext = SSLContext.getInstance(protocol);
		sslcontext.init(new KeyManager[] {km}, new TrustManager[] {tm}, null);

		return sslcontext;
	}

	private static void debugTS(X509CertChainValidator validator, String loginfo, Logger log)
	{
		X509Certificate trustedCerts[] = validator.getTrustedIssuers();
		for (X509Certificate cert: trustedCerts)
		{
			log.trace("Initially trusted certificates for " + loginfo + ":\n" + 
					CertificateUtils.format(cert, FormatMode.FULL));
		}
	}
	
	private static void debugKS(X509Credential c, String loginfo, Logger log)
	{
		X509Certificate[] certs = c.getCertificateChain();
		X509Certificate[] certs509 = CertificateUtils.convertToX509Chain(certs);
		log.trace("Client's certificate chain for " + loginfo + ": " + 
				CertificateUtils.format(certs509, FormatMode.FULL));
	}	
}
