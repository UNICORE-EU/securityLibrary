/**
 * Copyright (c) 2005, Forschungszentrum Juelich
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met: 
 * 
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of the Forschungszentrum Juelich nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package eu.unicore.security.util;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.Properties;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.unicore.security.util.client.DefaultAuthnConfigurationImpl;
import eu.unicore.security.util.client.IAuthenticationConfiguration;


/**
 * Class wrapping all security related settings for a UNICORE client or server:
 * truststore configuration and credentials. Additionally it is possible to retrieve 
 * {@link IAuthenticationConfiguration} implementation, which is the {@link DefaultAuthnConfigurationImpl}
 * based on the truststore and credentials.
 * 
 * @author K. Benedyczak
 */
public class AuthnAndTrustProperties
{
	private TruststorePropertiesConfig truststoreConfig;
	private CredentialPropertiesConfig credentialConfig;
	private IAuthenticationConfiguration authnConfiguration;
	
	public AuthnAndTrustProperties(String file) throws IOException, ConfigurationException
	{
		this(FilePropertiesHelper.load(file));
	}

	public AuthnAndTrustProperties(File f) throws IOException, ConfigurationException
	{
		this(f.getPath());
	}
	
	public AuthnAndTrustProperties(Properties p) throws ConfigurationException
	{
		truststoreConfig = new TruststorePropertiesConfig(p, 
			Collections.singleton(new LoggingStoreUpdateListener()));
		credentialConfig = new CredentialPropertiesConfig(p);
		authnConfiguration = new DefaultAuthnConfigurationImpl(
			getValidator(), getCredential());
	}

	public X509CertChainValidator getValidator()
	{
		return truststoreConfig.getValidator();
	}
	
	public X509Credential getCredential()
	{
		return credentialConfig.getCredential();
	}
	
	public IAuthenticationConfiguration getAuthenticationConfiguration()
	{
		return authnConfiguration;
	}
}
