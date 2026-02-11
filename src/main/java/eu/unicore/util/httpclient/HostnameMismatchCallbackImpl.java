package eu.unicore.util.httpclient;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.logging.log4j.Logger;

import eu.emi.security.authn.x509.impl.HostnameMismatchCallback2;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.util.Log;

/**
 * Depending on the configured mode either log problems or log problems and close connections. 
 */
public class HostnameMismatchCallbackImpl implements HostnameMismatchCallback2
{
	private static final Logger log = Log.getLogger(Log.SECURITY, HostnameMismatchCallbackImpl.class);
	
	private ServerHostnameCheckingMode mode;
	
	public HostnameMismatchCallbackImpl(ServerHostnameCheckingMode mode) 
	{
		this.mode = mode;
	}
	
	@Override
	public void nameMismatch(X509Certificate peerCertificate, String hostName) throws CertificateException
	{
		if (mode == ServerHostnameCheckingMode.NONE)
			return;
		String message = "The server hostname is not matching its certificate subject. This might mean that" +
				" somebody is trying to perform a man-in-the-middle attack by pretending to be" +
				" the server you are trying to connect to. However it is also possible that" +
				" the server uses a certificate which was not associated with its address." +
				" The server DNS name is: '" + hostName + "' and its certificate subject is: '" +
				X500NameUtils.getReadableForm(peerCertificate.getSubjectX500Principal()) + "'.";
		if (mode == ServerHostnameCheckingMode.WARN)
		{
			log.warn(message);
			return;
		}
		
		log.error(message);
		throw new CertificateException(message);
	}
}
