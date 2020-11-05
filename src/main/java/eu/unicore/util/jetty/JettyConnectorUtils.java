/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.jetty;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;

import org.apache.logging.log4j.Logger;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.security.canl.SSLContextCreator;

/**
 * low level utility methods useful for secured Jetty connectors
 * @author K. Benedyczak
 */
public class JettyConnectorUtils
{
	public static SslContextFactory.Server createJettyContextFactory(X509CertChainValidator validator,
			X509Credential credential, Logger log) throws NoSuchAlgorithmException, 
			NoSuchProviderException, KeyManagementException
	{
		SslContextFactory.Server ret = new SslContextFactory.Server();
		String protocol = "TLS"; 
		ret.setSslContext(SSLContextCreator.createSSLContext(credential, validator, protocol, 
				"Jetty HTTP Server", log));
		return ret;
	}
	
	public static void logConnection(final Socket socket, final Logger log) {
		InetSocketAddress peer=(InetSocketAddress)socket.getRemoteSocketAddress();
		if(log.isDebugEnabled() && peer!=null && peer.getAddress()!=null){
			final String hostAddress = peer.getAddress().getHostAddress();
			log.debug("Connection attempt from " + hostAddress);

			if (socket instanceof SSLSocket)
			{
				SSLSocket ssl = (SSLSocket) socket;
				ssl.addHandshakeCompletedListener(new HandshakeCompletedListener() {
					public void handshakeCompleted(HandshakeCompletedEvent hce) {
						try {
							X509Certificate[] peer = CertificateUtils.convertToX509Chain(
									hce.getPeerCertificates());
							String msg = X500NameUtils.getReadableForm(peer[0].getSubjectX500Principal());
							log.debug("SSL connection with " + msg + ", connected from " + 
									hostAddress + " was established.");
						} catch (SSLPeerUnverifiedException spe) {
							log.debug("An identity of the peer connecting from " + hostAddress + 
									" was not established on TLS layer");
						}
					}
				});
			}
		}
	}

}
