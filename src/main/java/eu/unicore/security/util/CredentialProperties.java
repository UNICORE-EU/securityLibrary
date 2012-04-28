/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.DERCredential;
import eu.emi.security.authn.x509.impl.FormatMode;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.emi.security.authn.x509.impl.PEMCredential;



/**
 * This class allows for setting up {@link X509Credential}
 * (e.g. used to setup identity of a local SSL peer) from Java properties.
 * 
 * @author K. Benedyczak
 */
public class CredentialProperties extends PropertiesHelper
{
	private static final Logger log = Log.getLogger(Log.SECURITY, CredentialProperties.class);

	public static final String DEFAULT_PREFIX = "credential.";

	//common for all
	public static final String PROP_FORMAT = "format";
	public static final String FORMAT_JKS = "jks";
	public static final String FORMAT_PKCS12 = "pkcs12";
	public static final String FORMAT_DER = "der";
	public static final String FORMAT_PEM = "pem";

	public static final String PROP_LOCATION = "path";
	public static final String PROP_PASSWORD = "password";

	//type-specific
	public static final String PROP_KEY_LOCATION = "keyPath";
	public static final String PROP_KS_ALIAS = "keyAlias";
	public static final String PROP_KS_KEY_PASSWORD = "keyPassword";

	private static final Map<String, PropertyMD> META = new HashMap<String, PropertyMD>();
	static
	{
		META.put(PROP_LOCATION, new PropertyMD().setMandatory().
				setDescription("credential location"));
		META.put(PROP_PASSWORD, new PropertyMD().setSecret());
		META.put(PROP_KS_KEY_PASSWORD, new PropertyMD().setSecret());
	}
	

	private String type;
	private String credPath;
	
	private X509Credential credential;
	
	private transient char[] mainPassword;
	private transient char[] keyPassword;
	
	/**
	 * Simple constructor: logging is turned on and standard properties prefix is used.
	 * @param properties properties object to read configuration from
	 * @throws ConfigurationException 
	 */
	public CredentialProperties(Properties properties) throws ConfigurationException
	{
		this(properties, null, null, DEFAULT_PREFIX);
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
		this(properties, null, null, pfx);
	}

	/**
	 * Allows for setting manually passwords (e.g. read from console
	 * or GUI).
	 * @param properties properties object to read configuration from
	 * @param mainPassword manually set credential's password, overrides properties setting
	 * @param keyPassword manually set credential's key password (used in JKS and PKCS12 only),
	 * overrides property setting
	 * @throws ConfigurationException 
	 */
	public CredentialProperties(Properties properties, char[] mainPassword, 
			char[] keyPassword) 
			throws ConfigurationException
	{
		this(properties, mainPassword, keyPassword, DEFAULT_PREFIX);
	}

	/**
	 * Allows for setting logging prefix and manually passwords (e.g. read from console
	 * or GUI).
	 * @param properties properties object to read configuration from
	 * @param pfx prefix to be used for properties. Should end with '.'!
	 * @param mainPassword manually set credential's password, overrides properties setting
	 * @param keyPassword manually set credential's key password (used in JKS and PKCS12 only),
	 * overrides property setting
	 * @throws ConfigurationException 
	 */
	public CredentialProperties(Properties properties, char[] mainPassword, 
			char[] keyPassword, String pfx) 
			throws ConfigurationException
	{
		super(pfx, properties, META, log);
		this.keyPassword = keyPassword;
		this.mainPassword = mainPassword;
		createCredentialSafe();
	}
	
	/**
	 * @return a previously loaded credential. 
	 */
	public X509Credential getCredential()
	{
		return credential;
	}

	private void createCredentialSafe() throws ConfigurationException
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
		} catch (CertificateExpiredException e)
		{
			log.warn("Certificate loaded from " + credPath + " (" + 
					CertificateUtils.format(cert, FormatMode.COMPACT_ONE_LINE) + ") " +
					" is EXPIRED: " + e.getMessage());
		} catch (CertificateNotYetValidException e)
		{
			log.warn("Certificate loaded from " + credPath + " (" + 
					CertificateUtils.format(cert, FormatMode.COMPACT_ONE_LINE) + ") " +
					" is NOT YED VALID: " + e.getMessage());
		} 
	}
	
	private void createCredential() throws ConfigurationException, 
		KeyStoreException, IOException, CertificateException
	{
		credPath = getFileValueAsString(PROP_LOCATION, false);
		log.debug("Credential file path: " + credPath);
		File ks = new File(credPath);
		if (!ks.exists() || !ks.canRead() || !ks.isFile())
			throw new ConfigurationException("Credential specified in the property " + 
					prefix + PROP_LOCATION + " must be an EXISTING, READABLE file: " + 
					credPath);

		char[] credPassword = mainPassword;
		if (mainPassword == null)
		{
			String pass = getValue(PROP_PASSWORD);
			credPassword = pass == null ? null : pass.toCharArray();
		} 
		
		String keyLocation = getFileValueAsString(PROP_KEY_LOCATION, false);
		String ksAlias = getValue(PROP_KS_ALIAS);
		char[] ksKeyPassword = keyPassword;
		if (keyPassword == null)
		{
			String pass = getValue(PROP_KS_KEY_PASSWORD);
			ksKeyPassword = pass == null ? null : pass.toCharArray();
		}
		
		type = getValue(PROP_FORMAT);
		if (type == null)
		{
			type = autodetectType(credPath, credPassword, keyLocation, 
				ksAlias, ksKeyPassword);
			log.info("Will use autodetected credential type >" + type + 
				"< for " + credPath);
		}
		log.debug("Credential type configured as: " + type);

		if (type.equalsIgnoreCase(FORMAT_JKS) || type.equalsIgnoreCase(FORMAT_PKCS12))
		{
			log.debug("Credential keystore alias: " + (ksAlias == null ? "NOT-SET" : ksAlias));
			if (credPassword == null)
				throw new ConfigurationException("For " + type + 
					" credential, the " + prefix + PROP_PASSWORD + 
					" property must be set and provide a keystore password");
			if (ksKeyPassword == null) 
			{
				log.debug("Using keystore password as key's password");
				ksKeyPassword = credPassword;
			}
			credential = new KeystoreCredential(credPath, credPassword, 
				ksKeyPassword, ksAlias, type.toUpperCase());
		} else if (type.equalsIgnoreCase(FORMAT_PEM))
		{
			log.debug("Credential's key file path: " + keyLocation);
			if (keyLocation == null)
				credential = new PEMCredential(credPath, credPassword);
			else
				credential = new PEMCredential(keyLocation, credPath, credPassword);
		} else if (type.equalsIgnoreCase(FORMAT_DER))
		{
			log.debug("Credential's key file path: " + keyLocation);
			if (keyLocation == null)
				throw new ConfigurationException("For " + FORMAT_DER + 
					" credential, the " + prefix + PROP_KEY_LOCATION + 
					" property must be set and point at the DER encoded private key.");
			credential = new DERCredential(keyLocation, credPath, credPassword);
		} else
			throw new ConfigurationException("Unknown type of credential used: " 
					+ type + " must be one of: " + FORMAT_JKS + ", " +
					FORMAT_PEM + ", " + FORMAT_PKCS12 + ", " + FORMAT_DER);
	}
	
	private String autodetectType(String credPath, char[] credPassword,
			String keyLocation, String ksAlias, char[] ksKeyPassword)
	{
		String errorPfx = "Credential type was not set with the property " 
				+ prefix + PROP_FORMAT;
		if (keyLocation != null && (ksAlias != null || ksKeyPassword != null))
			new ConfigurationException(errorPfx + " and settings for both " + 
					FORMAT_PEM + " and JKS/PKCS12 keystore are present." +
					" Either set the type explicitely or delete settings of not used credential type (" 
					+ PROP_KEY_LOCATION + " or " + PROP_KS_ALIAS + " and " + PROP_KS_KEY_PASSWORD +")");
		
		if (ksAlias != null || ksKeyPassword != null || keyLocation == null)
		{
			//ok - only JKS/PKCS12 possible
			try
			{
				return KeystoreCredential.autodetectType(credPath, credPassword);
			} catch (KeyStoreException e)
			{
				new ConfigurationException(errorPfx + ". Tried to load JKS/PKCS12 keystore as " +
						"settings for those types are present, but it was not possible. " +
						"Try to set the type explicitely and to review other credential settings.");
			} catch (IOException e)
			{
				new ConfigurationException(errorPfx + ". Tried to load JKS/PKCS12 keystore as " +
						"settings for those types are present, but it was not possible. " +
						"Try to set the type explicitely and to review other credential settings. " +
						"Cause: " + e.toString());
			}
				
		}

		//only PEM or DER
		if (credPath.endsWith("der") || (keyLocation != null && keyLocation.endsWith("der")) ||
				credPath.endsWith("pkcs8") || credPath.endsWith("pk8"))
			return FORMAT_DER;
		return FORMAT_PEM;
	}
}
