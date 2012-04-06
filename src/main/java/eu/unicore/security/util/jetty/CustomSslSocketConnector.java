/*********************************************************************************
 * Copyright (c) 2008 Forschungszentrum Juelich GmbH 
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
package eu.unicore.security.util.jetty;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.log4j.Logger;
import org.mortbay.jetty.security.SslSocketConnector;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.SocketFactoryCreator;
import eu.unicore.security.util.Log;
import eu.unicore.security.util.LoggingX509TrustManager;


/**
 * Extension of the Jetty {@link SslSocketConnector}, allowing to customise trust
 * management. Will also log the address of the remote host trying to 
 * establish a connection.
 */
public class CustomSslSocketConnector extends SslSocketConnector
{
	private final static Logger log = Log.getLogger(Log.CONNECTIONS, CustomSslSocketConnector.class);

	private final X509CertChainValidator validator;
	private final X509Credential credential;

	/**
	 * Creates Socket connector with provided validator and credential
	 * @param validator
	 * @param credential
	 */
	public CustomSslSocketConnector(X509CertChainValidator validator,
			X509Credential credential)
	{
		this.credential = credential;
		this.validator = validator;
	}

	@Override
	protected void configure(Socket socket)throws IOException{
		InetSocketAddress peer=(InetSocketAddress)socket.getRemoteSocketAddress();
		if(log.isDebugEnabled() && peer!=null && peer.getAddress()!=null){
			log.debug("Connection attempt from "+peer.getAddress().getHostAddress());
		}
		super.configure(socket);
	}

	@Override
	protected SSLServerSocketFactory createFactory() throws Exception  {
		SSLContext context = createSSLContext(validator, credential, getProtocol(), 
			getProvider(), getSecureRandomAlgorithm());
		return context.getServerSocketFactory();
	}
	
	public static SSLContext createSSLContext(X509CertChainValidator validator,
			X509Credential credential, String protocol, String provider,
			String secRandomAlg) throws NoSuchAlgorithmException, 
			NoSuchProviderException, KeyManagementException
	{
		KeyManager[] keyManagers = new KeyManager[] {credential.getKeyManager()};

		X509TrustManager trustManager = SocketFactoryCreator.getSSLTrustManager(validator);
		X509TrustManager decoratedTrustManager = new LoggingX509TrustManager(trustManager);
		TrustManager[] trustManagers = new X509TrustManager[] {decoratedTrustManager};;

		SecureRandom secureRandom = (secRandomAlg == null) ? 
				null : 
				SecureRandom.getInstance(secRandomAlg);
		SSLContext context = (provider == null) ? 
				SSLContext.getInstance(protocol) :
				SSLContext.getInstance(protocol, provider);

		context.init(keyManagers, trustManagers, secureRandom);
		return context;
	}
}
