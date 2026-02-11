package eu.unicore.security;

import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.unicore.util.httpclient.DefaultClientConfiguration;

/**
 * @author K. Benedyczak
 */
public class MockSecurityConfig extends DefaultClientConfiguration
{
	public static final String HTTP_PASSWD = "123";
	public static final String HTTP_USER = "qwer";
	
	public static final String KS = "src/test/resources/client/client.jks";
	public static final String KS_PASSWD = "the!client";

	public static final String KS_ALIAS = "mykey";
	public static final String KS_ALIAS_GW = "gw";
	public static final String KS_ALIAS_WRONG = "mykey_wrong";

	public MockSecurityConfig(boolean doHTTPAuthN,
			boolean doSSLAuthN, boolean correctSSLAuthN) throws Exception
	{
		setHttpAuthn(doHTTPAuthN);
		setSslAuthn(doSSLAuthN);
		setHttpPassword(HTTP_PASSWD);
		setHttpUser(HTTP_USER);
		if (doSSLAuthN)
		{
			setCredential(new KeystoreCredential(KS, 
				KS_PASSWD.toCharArray(), KS_PASSWD.toCharArray(), 
				correctSSLAuthN ? KS_ALIAS: KS_ALIAS_WRONG, 
				"JKS"));
		}
		setValidator(new KeystoreCertChainValidator(KS, KS_PASSWD.toCharArray(), 
				"JKS", -1));
	}

	@Override
	public MockSecurityConfig clone()
	{
		try
		{
			return (MockSecurityConfig) super.clone();
		} catch (Exception e)
		{
			throw new RuntimeException("Can't clone!");
		}
	}
}
