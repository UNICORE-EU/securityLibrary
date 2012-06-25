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
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.log4j.Logger;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.SocketFactoryCreator;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.security.canl.LoggingX509TrustManager;

/**
 * low level utility methods useful for secured Jetty connectors
 * @author K. Benedyczak
 */
public class JettyConnectorUtils
{
	public static SslContextFactory createJettyContextFactory(X509CertChainValidator validator,
			X509Credential credential) throws NoSuchAlgorithmException, 
			NoSuchProviderException, KeyManagementException
	{
		SslContextFactory ret = new SslContextFactory();
		//fix for IBM JDK where default protocol "TLS" does not work
		String vm=System.getProperty("java.vm.vendor");
		String protocol = "TLS"; 
		if(vm!=null && vm.trim().startsWith("IBM")){
			protocol = "SSL_TLS";//works for clients using both SSLv3 and TLS
		}
		ret.setSslContext(createSSLContext(validator, credential, protocol));
		return ret;
	}
	
	public static SSLContext createSSLContext(X509CertChainValidator validator,
			X509Credential credential, String protocol) throws NoSuchAlgorithmException, 
			NoSuchProviderException, KeyManagementException
	{
		KeyManager[] keyManagers = new KeyManager[] {credential.getKeyManager()};

		X509TrustManager trustManager = SocketFactoryCreator.getSSLTrustManager(validator);
		X509TrustManager decoratedTrustManager = new LoggingX509TrustManager(trustManager);
		TrustManager[] trustManagers = new X509TrustManager[] {decoratedTrustManager};;

		SSLContext context = SSLContext.getInstance(protocol);

		context.init(keyManagers, trustManagers, null);
		return context;
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
