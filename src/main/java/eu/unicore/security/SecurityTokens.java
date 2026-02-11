package eu.unicore.security;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.emi.security.authn.x509.proxy.ProxyUtils;

/**
 * A set of security tokens with authentication information collected and held 
 * during request processing.
 * 
 * E.g., the consignor and user are held here. Also trust delegation tokens 
 * and digital signature status are kept here. The additional data  
 * can be stored in a <i>context</i> map. Some keys of objects that can 
 * be found in the context are defined here too 
 * (e.g. HTTP BASIC Auth login and password).
 * <p>
 * Note about proxy certificates:
 * This class can recognize proxy certificates (for both user and consignor).
 * By default this support is turned on. When proxy support is turned on 
 * the object will return an EEC for the call to {@link #getConsignorCertificate()} 
 * 
 * @author K. Benedyczak
 * @author Bernd Schuller
 */
public class SecurityTokens implements Serializable, Cloneable
{
	private static final long serialVersionUID = 1L;

	/**
	 * Key for storing the security tokens in the message context.
	 */
	public static final String KEY = SecurityTokens.class.getName() + ".key";

	
	/**
	 * Context key of the token (as found in Unicore6Tokens) with HTTP BASIC login data.
	 * The value corresponding to this key is either null or {@link HTTPAuthNTokens}.
	 */
	public static final String CTX_LOGIN_HTTP = HTTPAuthNTokens.class.getName() + ".key"; 

	/**
	 * Context key of the SOAP action being invoked. The value corresponding to 
	 * this key is either null or a String. 
	 */
	public static final String CTX_SOAP_ACTION = "REQUEST.soapAction";

	/**
	 * Context key of String which denotes if the request is done as normal WS request.
	 */
	public static final String CTX_SCOPE_KEY = SecurityTokens.class.getName() + ".scope";

	/**
	 * Standard value of SCOPE_KEY.
	 */
	public static final String SCOPE_REQUEST = "request";

	private transient X509Certificate[] user;
	private transient X509Certificate[] consignor;

	private String userName;
	private String consignorName;
	private String clientIP;
	
	private final Map<String, String[]> userPreferences = new HashMap<>();
	
	private transient Map<String, Object> context;
	
	/**
	 * If true then tdTokens confirmed that the User allowed the Consignor to act 
	 * on her behalf or Consignor is equal to User or this is a local call.
	 */
	private boolean consignorTrusted;

	private boolean supportProxy;

	/**
	 * With proxy support turned on
	 */
	public SecurityTokens()
	{
		this(true);
	}

	/**
	 * Allows to set proxy support
	 */
	public SecurityTokens(boolean supportProxy)
	{
		this.supportProxy = supportProxy;
		context = new HashMap<>();
	}

	public SecurityTokens clone()throws CloneNotSupportedException{
		SecurityTokens clone=(SecurityTokens)super.clone();
		return clone;
	}
	/**
	 * Sets a consignor. It should be a VALIDATED identity.
	 * @param consignor
	 */
	public void setConsignor(X509Certificate[] consignor)
	{
		this.consignor = consignor; 
		this.consignorName = consignor[0].getSubjectX500Principal().getName();
	}

	/**
	 * Sets a consignor as a DN. It should be a VALIDATED identity.
	 * This method clears any consignor certificate previously set.
	 * @param consignorName
	 */
	public void setConsignorName(String consignorName)
	{
		this.consignorName = consignorName; 
		this.consignor = null;
	}

	/**
	 * Retrieves the stored consignor as a certificate path.
	 */
	public X509Certificate[] getConsignor()
	{
		return consignor;
	}

	/**
	 * Retrieves stored consignor as X509 certificate. In proxy mode the EEC certificate
	 * is returned.
	 */
	public X509Certificate getConsignorCertificate()
	{
		if (consignor != null)
		{
			if (supportProxy)
				return ProxyUtils.getEndUserCertificate(consignor);
			else
				return consignor[0];
		}
		return null;
	}
	
	/**
	 * Sets user identity in terms of certificates. It is an identity of a user on 
	 * whose behalf consignor wishes to execute the request. 
	 * It has not to be verified, i.e. it can be just a requested user.
	 * @param user
	 */
	public void setUser(X509Certificate[] user)
	{
		this.user = user;
		X509Certificate userCert = getUserCertificate();
		if (userCert != null)
			this.userName = userCert.getSubjectX500Principal().getName();
	}

	/**
	 * Returns user's certificates path. Note that it <b>may not represent a 
	 * valid user</b>, i.e. there might 
	 * be no trust delegation chain from the returned user to the actual consignor.
	 */
	public X509Certificate[] getUser()
	{
		return user;
	}

	/**
	 * Sets user identity in terms of DN. It is identity of user on 
	 * whose behalf consignor wishes to execute the request. 
	 * It has not to be verified, i.e. it can be just a requested user.
	 * <p>
	 * Note that calling this method will clear user's certificate if it was stored
	 * before with setUser()!
	 *  
	 * @param userName
	 */
	public void setUserName(String userName)
	{
		this.userName = userName;
		user = null;
	}

	/**
	 * Returns a user's X509 certificate. Note that it <b>may not represent a 
	 * valid user</b>, i.e. there might 
	 * be no trust delegation chain from the returned user to the actual consignor.
	 * @return null if user is not set as certificate, user certificate otherwise
	 */
	public X509Certificate getUserCertificate()
	{
		if (user == null)
			return null;

		return user[0];
	}

	/**
	 * Returns a user's DN. Note that it <b>may not represent a 
	 * valid user</b>, i.e. there may 
	 * be no trust delegation chain from the returned user to the actual consignor.
	 * In proxy mode this method will return DN of EEC only if certificate (with proxies)
	 * was also set. Otherwise the same userName as was set is returned.
	 */
	public String getUserName()
	{
		if (userName != null)
			return userName;
		return null;
	}

	/**
	 * Returns a consignor's DN. In proxy mode the consignor's EEC DN is returned.
	 */
	public String getConsignorName()
	{
		if (consignor != null)
			return getConsignorCertificate().getSubjectX500Principal().getName();
		else
			return consignorName;
	}

	/**
	 * Returns effective user certificate, i.e. the <i>user</i> (if there is a valid 
	 * trust delegation
	 * from the user to the consignor) or the <i>consignor</i> (in other cases). 
	 * This method will return null when the consignor is unknown.
	 */
	public X509Certificate getEffectiveUserCertificate()
	{
		if (user != null && consignorTrusted)
			return getUserCertificate();
		return getConsignorCertificate();
	}

	/**
	 * Returns effective user DN, i.e. the <i>user</i> (if there is a valid 
	 * trust delegation
	 * from the user to the consignor) or the <i>consignor</i> (in other cases).
	 * This method will return null when the consignor is unknown.
	 */
	public String getEffectiveUserName()
	{
		if (userName != null && consignorTrusted)
			return getUserName();
		return getConsignorName();
	}


        private static final String lineSep=System.getProperty("line.separator");

        public String toString()
        {
        	StringBuilder sb = new StringBuilder();
        	if (userName != null) {
        		sb.append("User: ").append(X500NameUtils.getReadableForm(userName));
        	}
        	String consignor = getConsignorName(); 
    		if (consignor != null) {
        		sb.append(lineSep);
        		sb.append("Consignor: ").append(X500NameUtils.getReadableForm(consignor));
    		}
        	if (clientIP != null) {
        		sb.append(lineSep).append("Client's original IP: ").append(clientIP);
        	}
        	if (sb.length() == 0) {
        		sb.append(super.toString()).append(" [no details available]");
        	}
        	return sb.toString();
        }

	/**
	 * Returns a map with additional security related data. This can be used 
	 * by handlers to store additional data to be used during request processing.
	 * NOTE: this information is only available during request processing and is never stored.
	 * To store something permanently, use {@link #getUserPreferences()}
	 */
	public synchronized Map<String, Object> getContext()
	{
		return context;
	}

	/**
	 * Returns a map holding the user's preferences (xlogin, groups, ...)
	 */
	public Map<String, String[]> getUserPreferences()
	{
		return userPreferences;
	}

	/**
	 * @return true only if the consignor's certificate is a proxy and proxy support is turned on.
	 */
	public boolean isConsignorUsingProxy()
	{
		if (consignor != null && supportProxy)
		{
			return ProxyUtils.isProxy(consignor);
		}
		return false;
	}

	/**
	 * @return the identity of the real consignor's certificate. In case of proxies it can be different
	 * from the value returned by the {@link #getConsignorName()}
	 */
	public String getConsignorRealName()
	{
		if (consignor != null)
		{
			return consignor[0].getSubjectX500Principal().getName();
		}
		return consignorName;
	}
	
	/**
	 * Returns true if the Consignor is anyhow allowed to work on
	 * User's behalf, as set by the setConsignorTrusted method. 
	 */
	public boolean isConsignorTrusted()
	{
		return consignorTrusted;
	}

	public boolean isSupportingProxy()
	{
		return supportProxy;
	}
	
	/**
	 * Sets the key value telling if the Consignor is allowed to work on 
	 * the Users behalf. 
	 */
	public void setConsignorTrusted(boolean consignorTrusted)
	{
		this.consignorTrusted = consignorTrusted;
	}

	/**
	 * @return the real client's IP as obtained from gateway or local network stack
	 */
	public String getClientIP() {
		return clientIP;
	}

	/**
	 * Sets client's IP
	 */
	public void setClientIP(String clientIP) {
		this.clientIP = clientIP;
	}

	/**
	 * Two sets of tokes are considered equal if their effective user names, 
	 * consignor names, delegation statuses and signature status are equal.
	 * Also proxy mode and client's IP must be the same.
	 */
	public boolean equals(Object otherO)
	{
		if (otherO == null || !(otherO instanceof SecurityTokens))
		{
			return false;
		}
		SecurityTokens other = (SecurityTokens) otherO;

		if (other.isConsignorTrusted() != isConsignorTrusted())
			return false;
		
		if (other.getConsignorName() == null)
		{
			if (getConsignorName() != null)
				return false;
		} else if (!other.getConsignorName().equals(getConsignorName()))
			return false;
		
		
		if (other.getEffectiveUserName() == null)
		{
			if (getEffectiveUserName() != null)
				return false;
		} else if (!other.getEffectiveUserName().equals(getEffectiveUserName()))
			return false;
		
		if (other.supportProxy != supportProxy)
			return false;
		
		if (other.getClientIP() == null)
		{
			if (getClientIP() != null)
				return false;
		} else if (!other.getClientIP().equals(getClientIP()))
			return false;
		
		return true;
	}

	public int hashCode(){
		String cons = getConsignorName();
		int consignorHash = cons == null ? 0 : cons.hashCode(); 
		String user = getEffectiveUserName();
		int userHash = user == null ? 0 : user.hashCode();
		return (isConsignorTrusted()?0x1:0x0)
				^ consignorHash
				^ userHash;
	}
}












