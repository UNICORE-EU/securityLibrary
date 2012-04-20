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
import java.security.cert.X509Certificate;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;

import org.apache.log4j.Logger;
import org.mortbay.jetty.security.SslSelectChannelConnector;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.security.util.Log;

/**
 * Extension of the Jetty {@link SslSelectChannelConnector}, allowing to customise trust
 * management. Will also log the address of the remote host trying to 
 * establish a connection.
 * 
 * @author schuller
 * @author golbi
 */
public class NIOSSLSocketConnector extends SslSelectChannelConnector {
	
	private final static Logger log = Log.getLogger(Log.CONNECTIONS, NIOSSLSocketConnector.class);
	
	private final X509CertChainValidator validator;
	private final X509Credential credential;
	
	public NIOSSLSocketConnector(X509CertChainValidator validator,
			X509Credential credential)
	{
		this.credential = credential;
		this.validator = validator;
	}
	
	@Override
	protected SSLContext createSSLContext() throws Exception
	{
		return CustomSslSocketConnector.createSSLContext(validator, credential, 
			getProtocol(), getProvider(), getSecureRandomAlgorithm());
	}

	@Override
	protected void configure(Socket socket)throws IOException{
		logConnection(socket, log);
		super.configure(socket);
	}
	
	public static void logConnection(final Socket socket, final Logger log) {
		InetSocketAddress peer=(InetSocketAddress)socket.getRemoteSocketAddress();
		if(log.isDebugEnabled() && peer!=null && peer.getAddress()!=null){
			final String hostAddress = peer.getAddress().getHostAddress();
			log.debug("Connection attempt from " + hostAddress);

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








