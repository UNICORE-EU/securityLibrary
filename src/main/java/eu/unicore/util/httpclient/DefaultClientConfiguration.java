package eu.unicore.util.httpclient;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.X509Credential;
import eu.unicore.security.canl.DefaultAuthnAndTrustConfiguration;
import eu.unicore.util.configuration.PropertiesHelper;


/**
 * A default implementation of the {@link IClientConfiguration} interface
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
	private boolean useSecuritySessions = true;
	private boolean sslEnabled;
	private boolean doSignMessage;
	private int maxWSRetries=1;
	private long retryDelay=0;
	private Map<String,String[]> requestedAttributes = new HashMap<>();
	private Map<String, Object> extraSecurityTokens = new HashMap<>();
	private ServerHostnameCheckingMode serverHostnameCheckingMode = ServerHostnameCheckingMode.NONE;
	private HttpClientProperties httpClientProperties = new HttpClientProperties(new Properties());
	private final Map<Class<? extends PropertiesHelper>,PropertiesHelper> extraConfigurationHandlers 
			= new HashMap<>();

	private SessionIDProvider sessionIDProvider = new SessionIDProviderImpl();
	
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
	
	@Override
	public SessionIDProvider getSessionIDProvider() {
		return sessionIDProvider;
	}

	public void setSessionIDProvider(SessionIDProvider sessionIDProvider) {
		this.sessionIDProvider = sessionIDProvider;
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
	 * @param doSignMessage the doSignMessage to set
	 */
	public void setDoSignMessage(boolean doSignMessage)
	{
		this.doSignMessage = doSignMessage;
	}
	
	@Override
	public Map<String,String[]> getRequestedUserAttributes()
	{
		return requestedAttributes;
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

	@Override
	public int getMaxWSRetries()
	{
		return maxWSRetries;
	}

	public void setMaxWSRetries(int max)
	{
		this.maxWSRetries = max;
	}
	
	@Override
	public long getRetryDelay()
	{
		return retryDelay;
	}
	
	public void setRetryDelay(long delay)
	{
		this.retryDelay = delay;
	}
	
	/**
	 * for implementing clone in subclasses
	 * @param ret
	 */
	protected IClientConfiguration cloneTo(DefaultClientConfiguration ret)
	{
		ret.setCredential(getCredential());
		ret.setDoSignMessage(doSignMessage);
		Map<String, Object> extra = new HashMap<>();
		extra.putAll(extraSecurityTokens);
		ret.getRequestedUserAttributes().putAll(requestedAttributes);
		ret.setExtraSecurityTokens(extra);
		ret.setHttpAuthn(httpAuthn);
		ret.setHttpPassword(httpPassword);
		ret.setHttpUser(httpUser);
		ret.setSslAuthn(sslAuthn);
		ret.setSslEnabled(sslEnabled);
		ret.setValidator(getValidator());
		ret.setServerHostnameCheckingMode(serverHostnameCheckingMode);
		ret.setHttpClientProperties(httpClientProperties.clone());
		ret.setMessageLogging(messageLogging);
		ret.setUseSecuritySessions(useSecuritySessions);
		ret.setSessionIDProvider(sessionIDProvider);
		ret.extraConfigurationHandlers.putAll(extraConfigurationHandlers);
		ret.setRetryDelay(retryDelay);
		ret.setMaxWSRetries(maxWSRetries);
		return ret;
	}
}
