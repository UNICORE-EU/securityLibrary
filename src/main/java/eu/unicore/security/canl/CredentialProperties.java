/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.canl;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.logging.log4j.Logger;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.DERCredential;
import eu.emi.security.authn.x509.impl.FormatMode;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.util.Log;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.configuration.PropertiesHelper;
import eu.unicore.util.configuration.PropertyMD;



/**
 * This class allows for setting up {@link X509Credential}
 * (e.g. used to setup identity of a local SSL peer) from Java properties.
 * 
 * @author K. Benedyczak
 */
public class CredentialProperties extends PropertiesHelper
{
	private static final Logger log = Log.getLogger(Log.CONFIGURATION, CredentialProperties.class);

	private static final long WEEK=7*24*60*60*1000;
	public static final String DEFAULT_PREFIX = "credential.";

	//common for all
	public static final String PROP_FORMAT = "format";
	public enum CredentialFormat {jks, pkcs12, der, pem};

	public static final String PROP_LOCATION = "path";
	public static final String PROP_PASSWORD = "password";
	public static final String PROP_RELOAD_DYNAMICALLY= "reloadOnChange";
	
	//type-specific
	public static final String PROP_KEY_LOCATION = "keyPath";
	public static final String PROP_KS_ALIAS = "keyAlias";
	public static final String PROP_KS_KEY_PASSWORD = "keyPassword";

	public static final Map<String, PropertyMD> META = new HashMap<String, PropertyMD>();
	static
	{
		META.put(PROP_LOCATION, new PropertyMD().setMandatory().setSortKey("1").
				setDescription("Credential location. In case of 'jks', 'pkcs12' and 'pem' store it is the only location required. In case when credential is provided in two files, it is the certificate file path.").setPath());
		META.put(PROP_FORMAT, new PropertyMD().setEnum(CredentialFormat.jks).setSortKey("2").
				setDescription("Format of the credential. It is guessed when not given. Note that 'pem' might be either a PEM keystore with certificates and keys (in PEM format) or a pair of PEM files (one with certificate and second with private key)."));
		META.put(PROP_PASSWORD, new PropertyMD().setSecret().setSortKey("3").
				setDescription("Password required to load the credential."));
		META.put(PROP_KEY_LOCATION, new PropertyMD().setSortKey("4").
				setDescription("Location of the private key if stored separately from the main credential (applicable for 'pem' and 'der' types only),"));
		META.put(PROP_KS_KEY_PASSWORD, new PropertyMD().setSecret().setSortKey("5").
				setDescription("Private key password, which might be needed only for 'jks' or 'pkcs12', if key is encrypted with different password then the main credential password."));
		META.put(PROP_KS_ALIAS, new PropertyMD().setSortKey("6").
				setDescription("Keystore alias of the key entry to be used. Can be ignored if the keystore contains only one key entry. Only applicable for 'jks' and 'pkcs12'."));
		META.put(PROP_RELOAD_DYNAMICALLY, new PropertyMD("true").setBoolean().setSortKey("6").
				setDescription("Monitor credential location and trigger dynamical reload if file changes."));
	}
	

	private CredentialFormat type;
	private String credPath;
	
	private X509Credential credential;
	
	private PasswordCallback passwordCallback;
	
	/**
	 * Simple constructor: standard properties prefix is used, no password callback.
	 * @param properties properties object to read configuration from
	 * @throws ConfigurationException 
	 */
	public CredentialProperties(Properties properties) throws ConfigurationException
	{
		this(properties, null, DEFAULT_PREFIX);
	}

	/**
	 * Allows for setting logging prefix
	 * @param properties properties object to read configuration from
	 * @param pfx prefix to be used for properties. Should end with '.'!
	 * @throws ConfigurationException 
	 */
	public CredentialProperties(Properties properties, String pfx) 
			throws ConfigurationException
	{
		this(properties, null, pfx);
	}


	/**
	 * Allows for setting password callback (e.g. to read from console or GUI).
	 * @param properties properties object to read configuration from
	 * @param callback callback used to load the password if it was not specified in the properties
	 * @throws ConfigurationException 
	 */
	public CredentialProperties(Properties properties, PasswordCallback callback) 
			throws ConfigurationException
	{
		this(properties, callback, DEFAULT_PREFIX);
	}

	/**
	 * Allows for setting properties prefix and manually passwords (e.g. read from console
	 * or GUI).
	 * @param properties properties object to read configuration from
	 * @param callback callback used to load the password if it was not specified in the properties
	 * @param pfx prefix to be used for properties. Should end with '.'!
	 * @throws ConfigurationException 
	 */
	public CredentialProperties(Properties properties, PasswordCallback callback, String pfx) 
			throws ConfigurationException
	{
		super(pfx, properties, META, log);
		this.passwordCallback = callback;
		createCredentialSafe();
	}
	
	/**
	 * @return a previously loaded credential. 
	 */
	public X509Credential getCredential()
	{
		return credential;
	}

	protected void createCredentialSafe() throws ConfigurationException
	{
		try
		{
			createCredential();
		} catch (ConfigurationException e)
		{
			throw e;
		} catch (Exception e)
		{
			throw new ConfigurationException("There was a problem loading the credential " 
					+ credPath + " (type: " + type + "): " + e.getMessage(), 
					e);
		}

		X509Certificate cert = credential.getCertificate();
		try
		{
			cert.checkValidity();
			try 
			{
				cert.checkValidity(new Date(System.currentTimeMillis()+WEEK));
			} catch(CertificateExpiredException ce){
				String date=cert.getNotAfter().toString(); 
				log.warn("Credential certificate with DN " + 
						X500NameUtils.getReadableForm(cert.getSubjectX500Principal())+ 
						" will soon expire. The validity period ends " + date);
			}
		} catch (CertificateExpiredException e)
		{
			throw new ConfigurationException("Certificate loaded from " + credPath + " (" + 
					CertificateUtils.format(cert, FormatMode.COMPACT_ONE_LINE) + ") " +
					" is EXPIRED: " + e.getMessage());
		} catch (CertificateNotYetValidException e)
		{
			throw new ConfigurationException("Certificate loaded from " + credPath + " (" + 
					CertificateUtils.format(cert, FormatMode.COMPACT_ONE_LINE) + ") " +
					" is NOT YET VALID: " + e.getMessage());
		} 
	}
	
	protected void createCredential() throws ConfigurationException, 
		KeyStoreException, IOException, CertificateException
	{
		credPath = getFileValueAsString(PROP_LOCATION, false);
		File ks = new File(credPath);
		if (!ks.exists() || !ks.canRead() || !ks.isFile())
			throw new ConfigurationException("Credential specified in the property " + 
					prefix + PROP_LOCATION + " must be an EXISTING, READABLE file: " + 
					credPath);

		boolean preferCallback = passwordCallback != null && passwordCallback.ignoreProperties();
		char[] credPassword = null;
		if (!preferCallback)
		{
			String pass = getValue(PROP_PASSWORD);
			credPassword = pass == null ? null : pass.toCharArray();
		}
		if (credPassword == null && passwordCallback != null)
		{
			credPassword = passwordCallback.getPassword("credential", credPath);
		}
		
		String keyLocation = getFileValueAsString(PROP_KEY_LOCATION, false);
		String ksAlias = getValue(PROP_KS_ALIAS);
		char[] ksKeyPassword = null;
		if (!preferCallback)
		{
			String pass = getValue(PROP_KS_KEY_PASSWORD);
			ksKeyPassword = pass == null ? null : pass.toCharArray();
		}

		type = getEnumValue(PROP_FORMAT, CredentialFormat.class);
		if (type == null)
		{
			type = autodetectType(credPath, credPassword, keyLocation, 
				ksAlias, ksKeyPassword);
			log.info("Will use autodetected credential type >" + type + 
				"< for " + credPath);
		}

		if (type.equals(CredentialFormat.jks) || type.equals(CredentialFormat.pkcs12))
		{
			log.debug("Credential keystore alias: " + (ksAlias == null ? "NOT-SET" : ksAlias));
			if (credPassword == null)
				throw new ConfigurationException("For " + type + 
					" credential, the " + prefix + PROP_PASSWORD + 
					" property must be set and provide a keystore password");
			if (ksKeyPassword == null && passwordCallback != null && passwordCallback.askForSeparateKeyPassword())
			{
				ksKeyPassword = passwordCallback.getPassword("credential's key", credPath);
			}
			
			if (ksKeyPassword == null) 
			{
				log.debug("Using keystore password as key's password");
				ksKeyPassword = credPassword;
			}
			credential = new KeystoreCredential(credPath, credPassword, 
				ksKeyPassword, ksAlias, type.name());
		} else if (type.equals(CredentialFormat.pem))
		{
			if (keyLocation == null)
				credential = new PEMCredential(credPath, credPassword);
			else
				credential = new PEMCredential(keyLocation, credPath, credPassword);
		} else if (type.equals(CredentialFormat.der))
		{
			if (keyLocation == null)
				throw new ConfigurationException("For " + CredentialFormat.der + 
					" credential, the " + prefix + PROP_KEY_LOCATION + 
					" property must be set and point at the DER encoded private key.");
			credential = new DERCredential(keyLocation, credPath, credPassword);
		} else
			throw new ConfigurationException("Unknown type of credential used: " 
					+ type + " must be one of: " + 
					Arrays.toString(CredentialFormat.values()));
	}
	
	protected CredentialFormat autodetectType(String credPath, char[] credPassword,
			String keyLocation, String ksAlias, char[] ksKeyPassword)
	{
		String errorPfx = "Credential type was not set with the property " 
				+ prefix + PROP_FORMAT;
		if (keyLocation != null && (ksAlias != null || ksKeyPassword != null))
			throw new ConfigurationException(errorPfx + " and settings for both " + 
					CredentialFormat.pem + " and JKS/PKCS12 keystore are present." +
					" Either set the type explicitely or delete settings of not used credential type (" 
					+ PROP_KEY_LOCATION + " or " + PROP_KS_ALIAS + " and " + PROP_KS_KEY_PASSWORD +")");
		
		if (ksAlias != null || ksKeyPassword != null || keyLocation == null)
		{
			//possible: JKS, PKCS12 and PEM keystore
			if (credPath.toLowerCase().endsWith("pem"))
				return CredentialFormat.pem;
			
			//possible: JKS, PKCS12
			try
			{
				String type = KeystoreCredential.autodetectType(credPath, credPassword);
				if (type.equalsIgnoreCase("jks"))
					return CredentialFormat.jks;
				if (type.equalsIgnoreCase("pkcs12"))
					return CredentialFormat.pkcs12;
				else
					throw new ConfigurationException("Unknown keystore type found: " + type);
			} catch (KeyStoreException e)
			{
				throw new ConfigurationException(errorPfx + ". Tried to load JKS/PKCS12 keystore as " +
						"settings for those types are present, but it was not possible. " +
						"Try to set the credential format explicitely and/or to review other credential settings.");
			} catch (IOException e)
			{
				throw new ConfigurationException(errorPfx + ". Tried to load JKS/PKCS12 keystore as " +
						"settings for those types are present, but it was not possible. " +
						"Try to set the credential format explicitely and/or to review other credential settings. " +
						"Cause: " + e.toString());
			}
				
		}

		//only PEM or DER
		if (credPath.endsWith("der") || (keyLocation != null && keyLocation.endsWith("der")) ||
				credPath.endsWith("pkcs8") || credPath.endsWith("pk8"))
			return CredentialFormat.der;
		return CredentialFormat.pem;
	}

	public boolean isDynamicalReloadEnabled() {
		return getBooleanValue(PROP_RELOAD_DYNAMICALLY);
	}
	
	public void reloadCredential() throws ConfigurationException {
		if(isDynamicalReloadEnabled()) {
			createCredentialSafe();
		}
	}

	public CredentialProperties clone()
	{
		CredentialProperties ret = new CredentialProperties(properties, passwordCallback, prefix);
		super.cloneTo(ret);
		return ret;
	}
	
	
}
