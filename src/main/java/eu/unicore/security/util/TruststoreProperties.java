/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.log4j.Logger;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.CRLParameters;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.impl.DirectoryCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.RevocationParametersExt;
import eu.emi.security.authn.x509.impl.ValidatorParams;
import eu.emi.security.authn.x509.impl.ValidatorParamsExt;



/**
 * This class allows for setting up trust management (e.g. used to verify
 * certificates of SSL peers) from Java properties.
 * <p>
 * The class maintains a reference to the created validator and can try to update
 * its configuration upon request.
 *  
 * @author K. Benedyczak
 */
public class TruststoreProperties extends PropertiesHelper
{
	private static final Logger log = Log.getLogger(Log.SECURITY, TruststoreProperties.class);

	public static final String DEFAULT_PREFIX = "truststore.";
	
	//common for all
	public static final String PROP_TYPE = "type";
	public static final String TYPE_KEYSTORE = "keystore";
	public static final String TYPE_OPENSSL = "openssl";
	public static final String TYPE_DIRECTORY = "directory";

	public static final String PROP_UPDATE = "updateInterval";
	public static final String PROP_PROXY_SUPPORT = "allowProxy";
	public static final String PROP_CRL_MODE = "crlMode";

	//these are common for keystore and directory trust stores
	public static final String PROP_CRL_LOCATIONS = "crlLocations";
	public static final String PROP_CRL_UPDATE = "crlUpdateInterval";
	public static final String PROP_CRL_CONNECTION_TIMEOUT = "crlConnectionTimeout";
	public static final String PROP_CRL_CACHE_PATH = "crlDiskCachePath";
	
	//the rest is store dependent
	public static final String PROP_KS_PATH = "keystorePath";
	public static final String PROP_KS_PASSWORD = "keystorePassword";
	public static final String PROP_KS_TYPE = "keystoreFormat";

	public static final String PROP_OPENSSL_DIR = "opensslPath";
	public static final String PROP_OPENSSL_NS_MODE = "opensslNsMode";
	
	public static final String PROP_DIRECTORY_LOCATIONS = "directoryLocations";
	public static final String PROP_DIRECTORY_ENCODING = "directoryEncoding";
	public static final String PROP_DIRECTORY_CONNECTION_TIMEOUT = "directoryConnectionTimeout";
	public static final String PROP_DIRECTORY_CACHE_PATH = "directoryDiskCachePath";
	
	private Collection<? extends StoreUpdateListener> initialListeners;
	private OpensslCertChainValidator opensslValidator = null;
	private DirectoryCertChainValidator directoryValidator = null;
	private KeystoreCertChainValidator ksValidator = null;
		
	public final static Map<String, String> DEFAULTS = new HashMap<String, String>();
	public final static Map<String, String> MANDATORY = new HashMap<String, String>();
	static 
	{
		DEFAULTS.put(PROP_PROXY_SUPPORT, "ALLOW");
		DEFAULTS.put(PROP_CRL_MODE, CrlCheckingMode.IF_VALID.name());
		DEFAULTS.put(PROP_UPDATE, "600");
		DEFAULTS.put(PROP_OPENSSL_NS_MODE, NamespaceCheckingMode.EUGRIDPMA_GLOBUS.name());
		DEFAULTS.put(PROP_OPENSSL_DIR, "/etc/grid-security/certificates" );
		DEFAULTS.put(PROP_CRL_UPDATE, "600");
		DEFAULTS.put(PROP_CRL_CONNECTION_TIMEOUT, "15");
		DEFAULTS.put(PROP_CRL_CACHE_PATH, null);
		DEFAULTS.put(PROP_DIRECTORY_ENCODING, "PEM");
		DEFAULTS.put(PROP_DIRECTORY_CONNECTION_TIMEOUT, "15");
		DEFAULTS.put(PROP_DIRECTORY_CACHE_PATH, null);
		
		MANDATORY.put(PROP_TYPE, "truststore type");
	}

	private String type;
	
	private ProxySupport proxySupport;
	private CrlCheckingMode crlMode;
	private long storeUpdateInterval;
	private NamespaceCheckingMode nsMode;
	private String opensslDir;
	private long crlUpdateInterval;
	private int crlConnectionTimeout;
	private String crlDiskCache;
	private List<String> crlLocations;
	private Encoding directoryEncoding;
	private List<String> directoryLocations;
	private int caConnectionTimeout;
	private String caDiskCache;
	
	private String ksPath;
	private transient char[] ksPassword;
	private String ksType;

	/**
	 * Simple constructor: logging is turned on and standard properties prefix is used.
	 * @param properties properties object to read configuration from
	 * @throws IOException 
	 * @throws ConfigurationException whenever configuration is wrong and validator can not be instantiated.
	 * @throws KeyStoreException 
	 */
	public TruststoreProperties(Properties properties, 
			Collection<? extends StoreUpdateListener> initialListeners) 
				throws ConfigurationException
	{
		this(properties, initialListeners, DEFAULT_PREFIX);
	}

	/**
	 * Allows for setting prefix
	 * @param properties properties object to read configuration from
	 * @param pfx prefix to be used for properties. Should end with '.'!
	 * @throws IOException 
	 * @throws ConfigurationException whenever configuration is wrong and validator can not be instantiated.
	 * @throws KeyStoreException 
	 */
	public TruststoreProperties(Properties properties, 
			Collection<? extends StoreUpdateListener> initialListeners, String pfx) 
				throws ConfigurationException
	{
		super(pfx, properties, DEFAULTS, MANDATORY, log);
		this.initialListeners = initialListeners;
		createValidatorSafe();
	}
	
	/**
	 * @return a configured validator. 
	 */
	public X509CertChainValidator getValidator()
	{
		if (type.equalsIgnoreCase(TYPE_KEYSTORE))
		{
			return ksValidator;
		} else if (type.equalsIgnoreCase(TYPE_OPENSSL))
		{
			return opensslValidator;
		} else if (type.equalsIgnoreCase(TYPE_DIRECTORY))
		{
			return directoryValidator;
		}
		throw new RuntimeException("BUG! After object construction type value is unknown: " + type);
	}

	/**
	 * Checks properties and tries to update the underlying validator whenever possible.
	 * Only few options can be modified at runtime.
	 * @throws ConfigurationException 
	 */
	public void update() throws ConfigurationException
	{
		long newUpdateInterval = getLongValue(PROP_UPDATE);
		if (newUpdateInterval != storeUpdateInterval)
		{
			if (opensslValidator != null)
				opensslValidator.setUpdateInterval(newUpdateInterval*1000);
			if (directoryValidator != null)
				directoryValidator.setTruststoreUpdateInterval(newUpdateInterval*1000);
			if (ksValidator != null)
				ksValidator.setTruststoreUpdateInterval(newUpdateInterval*1000);
			storeUpdateInterval = newUpdateInterval;
			log.info("Updated " + prefix+PROP_UPDATE + " value to " + storeUpdateInterval);
		}

		if (opensslValidator != null)
			return;
		
		long newCrlUpdateInterval = getLongValue(PROP_CRL_UPDATE, true);
		if (newCrlUpdateInterval != crlUpdateInterval)
		{
			if (directoryValidator != null)
				directoryValidator.setCRLUpdateInterval(newCrlUpdateInterval*1000);
			if (ksValidator != null)
				ksValidator.setCRLUpdateInterval(newCrlUpdateInterval*1000);
			crlUpdateInterval = newCrlUpdateInterval;
			log.info("Updated " + prefix+PROP_CRL_UPDATE + " value to " + crlUpdateInterval);
		}
		
		List<String> newCrlLocations = getLocations(PROP_CRL_LOCATIONS);
		if (!newCrlLocations.equals(crlLocations))
		{
			if (directoryValidator != null)
				directoryValidator.setCrls(newCrlLocations);
			if (ksValidator != null)
				ksValidator.setCrls(newCrlLocations);
			crlLocations = newCrlLocations;
			log.info("Updated " + prefix+PROP_CRL_LOCATIONS);
		}
		
		if (ksValidator != null)
			return;
		
		List<String> newDirectoryLocations = getLocations(PROP_DIRECTORY_LOCATIONS);
		if (!newDirectoryLocations.equals(directoryLocations))
		{
			directoryValidator.setCrls(newDirectoryLocations);
			directoryLocations = newDirectoryLocations;
			log.info("Updated " + prefix+PROP_DIRECTORY_LOCATIONS);
		}
	}

	private void createValidatorSafe() throws ConfigurationException
	{
		try
		{
			createValidator();
		} catch (KeyStoreException e)
		{
			throw new ConfigurationException("There was a problem setting up the " +
					"truststore of type " + type + ": " + e.getMessage(), 
					e);
		} catch (IOException e)
		{
			throw new ConfigurationException("There was a problem setting up the " +
					"truststore of type " + type + ": " + e.getMessage(), 
					e);
		}
	}
	
	private void createValidator() throws ConfigurationException,
			KeyStoreException, IOException
	{
		type = getValue(PROP_TYPE);
		log.debug("Truststore type configured as: " + type);
		storeUpdateInterval = getLongValue(PROP_UPDATE);
		
		setCrlCheckingMode();
		setProxySupport();
		
		if (type.equals(TYPE_KEYSTORE))
		{
			ksValidator = getKeystoreValidator();
		} else if (type.equals(TYPE_OPENSSL))
		{
			opensslValidator = getOpensslValidator();
		} else if (type.equals(TYPE_DIRECTORY))
		{
			directoryValidator = getDirectoryValidator();
		} else
			throw new ConfigurationException("Unknown type of keystore used: " 
					+ type + " must be one of: " + TYPE_DIRECTORY + ", " +
					TYPE_KEYSTORE + ", " + TYPE_OPENSSL);
	}

	
	
	private DirectoryCertChainValidator getDirectoryValidator() 
			throws ConfigurationException, KeyStoreException, IOException
	{
		setCrlSettings();
		directoryLocations = getLocations(PROP_DIRECTORY_LOCATIONS);
		setDirectoryEncoding();
		caConnectionTimeout = getIntValue(PROP_DIRECTORY_CONNECTION_TIMEOUT);
		caDiskCache = getDirectoryValue(PROP_DIRECTORY_CACHE_PATH, true);
		
		ValidatorParamsExt params = getValidatorParamsExt();
		return new DirectoryCertChainValidator(directoryLocations, directoryEncoding, 
			storeUpdateInterval*1000, caConnectionTimeout*1000, caDiskCache, params);
	}

	private OpensslCertChainValidator getOpensslValidator() throws ConfigurationException
	{
		setNsCheckingMode();
		opensslDir = getDirectoryValue(PROP_OPENSSL_DIR, false);

		RevocationParameters revocationSettings = new RevocationParameters(crlMode);
		ValidatorParams params = new ValidatorParams(revocationSettings, 
			proxySupport, initialListeners);
		return new OpensslCertChainValidator(opensslDir, nsMode, storeUpdateInterval*1000, 
			params);
	}

	private KeystoreCertChainValidator getKeystoreValidator() 
			throws ConfigurationException, KeyStoreException, IOException
	{
		setCrlSettings();
		ksPath = getValue(PROP_KS_PATH, true);
		if (ksPath == null)
			throw new ConfigurationException("Keystore path must be set, property: " + 
					prefix + PROP_KS_PATH);
		log.debug("Trust store keystore file path: " + ksPath);

		File ks = new File(ksPath);
		if (!ks.exists() || !ks.canRead() || !ks.isFile())
			throw new ConfigurationException("Keystore specified in the property " + 
					prefix + PROP_KS_PATH + " must be an EXISTING, READABLE file: " + 
					ksPath);

		String pass = getValue(PROP_KS_PASSWORD, true, true);
		if (pass == null)
			throw new ConfigurationException("Keystore password must be set, property: " + 
					prefix + PROP_KS_PASSWORD);
		ksPassword = pass.toCharArray();
		
		ksType = getValue(PROP_KS_TYPE, true);
		log.debug("Trust store keystore format: " + ksType);
		if (ksType == null)
			autodetectKeystoreType();
		
		ValidatorParamsExt params = getValidatorParamsExt();
		return new KeystoreCertChainValidator(ksPath, ksPassword, 
			ksType, storeUpdateInterval*1000, params);
	}	
	
	private void setCrlCheckingMode() throws ConfigurationException
	{
		String val = getValue(PROP_CRL_MODE);
		try
		{
			crlMode = CrlCheckingMode.valueOf(val);
		} catch (IllegalArgumentException e)
		{
			throw new ConfigurationException("Value " + val + " is not allowed for "
					+ prefix + PROP_CRL_MODE + ", valid values are: " + 
					Arrays.toString(CrlCheckingMode.values()));
		}
	}
	
	private void setProxySupport() throws ConfigurationException
	{
		String val = getValue(PROP_PROXY_SUPPORT);
		try
		{
			proxySupport = ProxySupport.valueOf(val);
		} catch (IllegalArgumentException e)
		{
			throw new ConfigurationException("Value " + val + " is not allowed for "
					+ prefix + PROP_PROXY_SUPPORT + ", valid values are: " + 
					Arrays.toString(ProxySupport.values()));
		}
	}

	private void setNsCheckingMode() throws ConfigurationException
	{
		String val = getValue(PROP_OPENSSL_NS_MODE);
		try
		{
			nsMode = NamespaceCheckingMode.valueOf(val);
		} catch (IllegalArgumentException e)
		{
			throw new ConfigurationException("Value " + val + " is not allowed for "
					+ prefix + PROP_OPENSSL_NS_MODE + ", valid values are: " + 
					Arrays.toString(NamespaceCheckingMode.values()));
		}
	}

	private void setDirectoryEncoding() throws ConfigurationException
	{
		String val = getValue(PROP_DIRECTORY_ENCODING);
		try
		{
			directoryEncoding = Encoding.valueOf(val);
		} catch (IllegalArgumentException e)
		{
			throw new ConfigurationException("Value " + val + " is not allowed for "
					+ prefix + PROP_DIRECTORY_ENCODING + ", valid values are: " + 
					Arrays.toString(Encoding.values()));
		}
	}
	
	private void setCrlSettings() throws ConfigurationException
	{
		crlUpdateInterval = getLongValue(PROP_CRL_UPDATE);
		crlConnectionTimeout = getIntValue(PROP_CRL_CONNECTION_TIMEOUT);
		crlDiskCache = getDirectoryValue(PROP_CRL_CACHE_PATH, true);
		crlLocations = getLocations(PROP_CRL_LOCATIONS);
	}
	
	private ValidatorParamsExt getValidatorParamsExt()
	{
		CRLParameters crlParameters = new CRLParameters(crlLocations, crlUpdateInterval, 
			crlConnectionTimeout, crlDiskCache);
		RevocationParametersExt revParams = new RevocationParametersExt(crlMode, 
			crlParameters);
		return new ValidatorParamsExt(revParams, proxySupport, initialListeners);
	}
	
	private void autodetectKeystoreType() throws ConfigurationException
	{
		try
		{
			ksType = KeystoreCredential.autodetectType(ksPath, ksPassword);
		} catch (Exception e)
		{
			throw new ConfigurationException("Truststore type is not " +
					"set in the property " + prefix + PROP_KS_TYPE + 
					" and its autodetection failed. Try to set it and also " +
					"review password and location - most probably those are wrong.");
		}
	}
	
	private String getDirectoryValue(String name, boolean acceptNoVal) 
			throws ConfigurationException
	{
		String val = getValue(name, acceptNoVal);
		if (val == null)
			return val;
			
		File f = new File(val);
		if (!f.exists() || !f.isDirectory() || !f.canRead())
			throw new ConfigurationException("Value of "
					+ prefix + name + ", must be a path of an EXISTING and READABLE directory.");
		return val;
	}
	
	private List<String> getLocations(String prefix2)
	{
		List<String> ret = new ArrayList<String>();
		String base = prefix + prefix2;
		Set<Object> keys = properties.keySet();
		for (Object keyO: keys)
		{
			String key = (String) keyO;
			if (key.startsWith(base))
			{
				String v = properties.getProperty(key);
				log.debug("Trust store parameter " + key + 
					", value of location is: " + v);
				ret.add(v);
			}
		}
		
		return ret;
	}
}
