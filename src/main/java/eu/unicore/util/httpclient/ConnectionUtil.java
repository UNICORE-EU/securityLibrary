package eu.unicore.util.httpclient;

import java.io.IOException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.apache.logging.log4j.Logger;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.SocketFactoryCreator2;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.security.canl.IAuthnAndTrustConfiguration;
import eu.unicore.util.Log;

/**
 * Additional connection related utility methods
 * @author K. Benedyczak
 */
public class ConnectionUtil
{
	/**
	 * Utility method to get a certificate of an SSL peer. The SSL connection is established and if 
	 * successful, the peers identity is returned.
	 * @param securityCfg
	 * @param url
	 * @return certificate
	 * @throws IOException 
	 * @throws UnknownHostException 
	 */
	public static X509Certificate[] getPeerCertificate(IAuthnAndTrustConfiguration securityCfg, String url, 
			int timeout, Logger logger) throws UnknownHostException, IOException {
		if (securityCfg == null || securityCfg.getValidator() == null ||
				securityCfg.getCredential() == null)
			throw new IllegalArgumentException("Can not establish peer's identity " +
					"without having credential and validator set.");
		URL u=new URL(url);
		SSLSocketFactory socketFactory = new SocketFactoryCreator2(securityCfg.getCredential(), 
				securityCfg.getValidator(), null).getSocketFactory();
		
		int port = u.getPort();
		if (port == -1)
			port = u.getDefaultPort();
		if (port == -1)
			port = 443;
		
		try(SSLSocket s = (SSLSocket) socketFactory.createSocket(u.getHost(), port)){
			s.setSoTimeout(timeout);
			X509Certificate[] peer = CertificateUtils.convertToX509Chain(s.getSession().getPeerCertificates());
			if (logger.isDebugEnabled()) {
				try{
					logger.debug("Got peer cert of <{}>\nName: {}\nIssued by: {}",
							url,
							X500NameUtils.getReadableForm(peer[0].getSubjectX500Principal()),
							X500NameUtils.getReadableForm(peer[0].getIssuerX500Principal()));
				} catch(Exception e) {
					Log.logException("Problem with certificate for <"+url+">",e,logger);
				}
			}
			return peer;
		}
	}
}
