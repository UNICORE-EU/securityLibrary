/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.util.httpclient;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.X509Credential;
import eu.unicore.security.canl.DefaultAuthnAndTrustConfiguration;
import eu.unicore.util.configuration.PropertiesHelper;


/**
 * A default implementation of the {@link IAuthenticationConfiguration} interface
 * which can be used to manually configure all aspects of the interface with constructor parameters.
 * 
 * @author golbi
 */
public class DefaultClientConfiguration extends DefaultAuthnAndTrustConfiguration implements IClientConfiguration
{
	private String httpUser;
	private String httpPassword;
	private boolean sslAuthn;
	private boolean httpAuthn;
	private boolean messageLogging;
	private boolean useSecuritySessions;
	private String[] inHandlerClassNames;
	private String[] outHandlerClassNames;
	private ClassLoader classLoader;
	private boolean sslEnabled;
	private boolean doSignMessage;
	private ETDClientSettings etdSettings = new ETDClientSettings();
	private Map<String, Object> extraSecurityTokens = new HashMap<String, Object>();
	private ServerHostnameCheckingMode serverHostnameCheckingMode = ServerHostnameCheckingMode.NONE;
	private HttpClientProperties httpClientProperties = new HttpClientProperties(new Properties());
	private final Map<Class<? extends PropertiesHelper>,PropertiesHelper> extraConfigurationHandlers 
			= new HashMap<Class<? extends PropertiesHelper>, PropertiesHelper>();

	/**
	 * Only default settings, i.e. no security.
	 */
	public DefaultClientConfiguration()
	{
	}

	/**
	 * This constructor is the typical for UNICORE: SSL and ssl authN is on, http authn is off. 
	 * @param validator
	 * @param credential
	 */
	public DefaultClientConfiguration(X509CertChainValidatorExt validator, X509Credential credential)
	{
		super(validator, credential);
		this.sslAuthn = true;
		this.sslEnabled = true;
		etdSettings.setIssuerCertificateChain(credential.getCertificateChain());
	}

	/**
	 * This method also updates issuer in ETD settings, which basically always must be set.
	 * @param credential the credential to set
	 */
	@Override
	public void setCredential(X509Credential credential)
	{
		super.setCredential(credential);
		if (getCredential() != null)
			etdSettings.setIssuerCertificateChain(credential.getCertificateChain());
	}

	/**
	 * @return the httpUser
	 */
	@Override
	public String getHttpUser()
	{
		return httpUser;
	}

	/**
	 * @param httpUser the httpUser to set
	 */
	public void setHttpUser(String httpUser)
	{
		this.httpUser = httpUser;
	}

	/**
	 * @return the httpPassword
	 */
	@Override
	public String getHttpPassword()
	{
		return httpPassword;
	}

	/**
	 * @param httpPassword the httpPassword to set
	 */
	public void setHttpPassword(String httpPassword)
	{
		this.httpPassword = httpPassword;
	}

	/**
	 * @return the sslAuthn
	 */
	@Override
	public boolean doSSLAuthn()
	{
		return sslAuthn;
	}

	/**
	 * @param sslAuthn the sslAuthn to set
	 */
	public void setSslAuthn(boolean sslAuthn)
	{
		this.sslAuthn = sslAuthn;
	}

	/**
	 * @return the httpAuthn
	 */
	@Override
	public boolean doHttpAuthn()
	{
		return httpAuthn;
	}

	/**
	 * @param httpAuthn the httpAuthn to set
	 */
	public void setHttpAuthn(boolean httpAuthn)
	{
		this.httpAuthn = httpAuthn;
	}

	/**
	 * @return the inHandlerClassNames
	 */
	@Override
	public String[] getInHandlerClassNames()
	{
		return inHandlerClassNames;
	}

	/**
	 * @param inHandlerClassNames the inHandlerClassNames to set
	 */
	public void setInHandlerClassNames(String[] inHandlerClassNames)
	{
		this.inHandlerClassNames = inHandlerClassNames;
	}

	/**
	 * @return the outHandlerClassNames
	 */
	@Override
	public String[] getOutHandlerClassNames()
	{
		return outHandlerClassNames;
	}

	/**
	 * @param outHandlerClassNames the outHandlerClassNames to set
	 */
	public void setOutHandlerClassNames(String[] outHandlerClassNames)
	{
		this.outHandlerClassNames = outHandlerClassNames;
	}

	/**
	 * @return the classLoader
	 */
	@Override
	public ClassLoader getClassLoader()
	{
		return classLoader;
	}

	/**
	 * @param classLoader the classLoader to set
	 */
	public void setClassLoader(ClassLoader classLoader)
	{
		this.classLoader = classLoader;
	}

	/**
	 * @return the sslEnabled
	 */
	@Override
	public boolean isSslEnabled()
	{
		return sslEnabled;
	}

	/**
	 * @param sslEnabled the sslEnabled to set
	 */
	public void setSslEnabled(boolean sslEnabled)
	{
		this.sslEnabled = sslEnabled;
	}

	@Override
	public boolean useSecuritySessions()
	{
		return useSecuritySessions;
	}

	/**
	 * @param useSecuritySessions - whether to enable sessions
	 */
	public void setUseSecuritySessions(boolean useSecuritySessions)
	{
		this.useSecuritySessions = useSecuritySessions;
	}
	
	/**
	 * @return the doSignMessages
	 */
	@Override
	public boolean doSignMessage()
	{
		return doSignMessage;
	}

	/**
	 * @param doSignMessages the doSignMessages to set
	 */
	public void setDoSignMessage(boolean doSignMessage)
	{
		this.doSignMessage = doSignMessage;
	}

	/**
	 * @return the etdClientSettings
	 */
	@Override
	public ETDClientSettings getETDSettings()
	{
		return etdSettings;
	}

	/**
	 * @param etdSettings the etdSettings to set
	 */
	public void setEtdSettings(ETDClientSettings etdSettings)
	{
		this.etdSettings = etdSettings;
	}

	/**
	 * @deprecated returns null 
	 */
	@Override
	@Deprecated
	public Properties getExtraSettings()
	{
		return null;
	}

	/**
	 * @param extraSettings the extraSettings to set
	 * @deprecated Not used anymore, no op
	 */
	@Deprecated
	public void setExtraSettings(Properties extraSettings)
	{
	}

	/**
	 * @return the extraSecurityTokens
	 */
	@Override
	public Map<String, Object> getExtraSecurityTokens()
	{
		return extraSecurityTokens;
	}

	/**
	 * @param extraSecurityTokens the extraSecurityTokens to set
	 */
	public void setExtraSecurityTokens(Map<String, Object> extraSecurityTokens)
	{
		this.extraSecurityTokens = extraSecurityTokens;
	}

	/**
	 * @return the serverHostnameCheckingMode
	 */
	@Override
	public ServerHostnameCheckingMode getServerHostnameCheckingMode()
	{
		return serverHostnameCheckingMode;
	}

	/**
	 * @param serverHostnameCheckingMode the serverHostnameCheckingMode to set
	 */
	public void setServerHostnameCheckingMode(ServerHostnameCheckingMode serverHostnameCheckingMode)
	{
		this.serverHostnameCheckingMode = serverHostnameCheckingMode;
	}

	public void setMessageLogging(boolean what)
	{
		this.messageLogging=what;
	}

	public boolean isMessageLogging()
	{
		return messageLogging;
	}

	/**
	 * Note - credential and validator objects are not cloned - are copied by reference.
	 * This doesn't affect threading (both are thread safe). Credential is usually immutable.
	 * Changes to validator settings will be visible also in the validator of the cloned object.
	 */
	@Override
	public DefaultClientConfiguration clone()
	{
		DefaultClientConfiguration ret = (DefaultClientConfiguration) super.clone();
		cloneTo(ret);
		return ret;
	}

	/**
	 * for implementing clone in subclasses
	 * @param ret
	 * @return
	 */
	protected IClientConfiguration cloneTo(DefaultClientConfiguration ret)
	{
		ret.setClassLoader(classLoader);
		ret.setCredential(getCredential());
		ret.setDoSignMessage(doSignMessage);
		ret.setEtdSettings(etdSettings.clone());
		Map<String, Object> extra = new HashMap<String, Object>();
		extra.putAll(extraSecurityTokens);
		ret.setExtraSecurityTokens(extra);
		ret.setHttpAuthn(httpAuthn);
		ret.setHttpPassword(httpPassword);
		ret.setHttpUser(httpUser);
		ret.setInHandlerClassNames(inHandlerClassNames);
		ret.setOutHandlerClassNames(outHandlerClassNames);
		ret.setSslAuthn(sslAuthn);
		ret.setSslAuthn(sslAuthn);
		ret.setSslEnabled(sslEnabled);
		ret.setValidator(getValidator());
		ret.setServerHostnameCheckingMode(serverHostnameCheckingMode);
		ret.setHttpClientProperties(httpClientProperties.clone());
		ret.setMessageLogging(messageLogging);
		ret.extraConfigurationHandlers.putAll(extraConfigurationHandlers);
		return ret;
	}

	@Override
	public HttpClientProperties getHttpClientProperties()
	{
		return httpClientProperties;
	}

	public void setHttpClientProperties(HttpClientProperties httpClientProperties)
	{
		this.httpClientProperties = httpClientProperties;
	}

	/**
	 * add a custom configuration source
	 */
	public void addConfigurationHandler(PropertiesHelper settings){
		extraConfigurationHandlers.put(settings.getClass(), settings);
	}

	/**
	 * returns the requested configuration handler 
	 * @param key - the configuration handler class used as key
	 * @return the configuration handler
	 */
	public <T extends PropertiesHelper> T getConfigurationHandler(Class<T>key){
		Object o=extraConfigurationHandlers.get(key);
		return  key.cast(o);
	}
}
