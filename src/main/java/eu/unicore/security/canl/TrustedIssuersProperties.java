/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.canl;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.impl.CRLParameters;
import eu.emi.security.authn.x509.impl.DirectoryCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.RevocationParametersExt;
import eu.emi.security.authn.x509.impl.ValidatorParams;
import eu.emi.security.authn.x509.impl.ValidatorParamsExt;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.unicore.util.Log;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.configuration.PropertiesHelper;
import eu.unicore.util.configuration.PropertyChangeListener;
import eu.unicore.util.configuration.PropertyMD;
import eu.unicore.util.configuration.PropertyMD.DocumentationCategory;



/**
 * This class allows for setting up a set of trusted certificates from Java properties.
 * This class is not configuring a full truststore with support for CRL checking and other features
 * useful for X.509 PKI scenarios as {@link TruststoreProperties}. It is merely configuring
 * a set of certificates (typically not CA certificates, but EEC certificates) 
 * which are recognized as special entities in the system. Typical applications are SAML scenarios
 * where trusted IdPs or trusted bootstrap ETD issuers must be configured.
 * <p>
 * Under the covers this class is using {@link X509CertChainValidator}, or strictly speaking its trust anchor store. 
 * It is because, we get for free support for multiple formats and autoupdate features.
 * <p>
 * 
 *  
 * @author K. Benedyczak
 */
public class TrustedIssuersProperties extends PropertiesHelper
{
	private static final Logger log = Log.get12Logger(Log.CONFIGURATION, TrustedIssuersProperties.class);

	public static final String DEFAULT_PREFIX = "trustedIssuers.";
	
	public enum TruststoreType {keystore, openssl, directory};
	//common for all
	public static final String PROP_TYPE = "type";

	public static final String PROP_UPDATE = "updateInterval";
	
	//the rest is store dependent
	public static final String PROP_KS_PATH = "keystorePath";
	public static final String PROP_KS_PASSWORD = "keystorePassword";
	public static final String PROP_KS_TYPE = "keystoreFormat";

	public static final String PROP_OPENSSL_DIR = "opensslPath";
	public static final String PROP_OPENSSL_NEW_STORE_FORMAT = "opensslNewStoreFormat";
	
	public static final String PROP_DIRECTORY_LOCATIONS = "directoryLocations.";
	public static final String PROP_DIRECTORY_ENCODING = "directoryEncoding";
	public static final String PROP_DIRECTORY_CONNECTION_TIMEOUT = "directoryConnectionTimeout";
	public static final String PROP_DIRECTORY_CACHE_PATH = "directoryDiskCachePath";
	
	private final static String[] UPDATEABLE_PROPS = {PROP_UPDATE, PROP_DIRECTORY_LOCATIONS};
	
	protected Collection<? extends StoreUpdateListener> initialListeners;
	protected OpensslCertChainValidator opensslValidator = null;
	protected DirectoryCertChainValidator directoryValidator = null;
	protected KeystoreCertChainValidator ksValidator = null;
		
	public final static Map<String, PropertyMD> META = new HashMap<String, PropertyMD>();
	static 
	{
		DocumentationCategory dirCat = new DocumentationCategory("Directory type settings", "1");
		DocumentationCategory ksCat = new DocumentationCategory("Keystore type settings", "2");
		DocumentationCategory opensslCat = new DocumentationCategory("Openssl type settings", "3");
		
		META.put(PROP_TYPE, new PropertyMD().setEnum(TruststoreType.directory).
				setMandatory().setDescription("The truststore type."));
		META.put(PROP_UPDATE, new PropertyMD("600").setLong().setUpdateable().
				setDescription("How often the truststore should be reloaded, in seconds. Set to negative value to disable refreshing at runtime."));

		META.put(PROP_KS_PASSWORD, new PropertyMD().setSecret().setCategory(ksCat).
				setDescription("The password of the keystore type truststore."));
		META.put(PROP_KS_TYPE, new PropertyMD().setCategory(ksCat).
				setDescription("The keystore type (jks, pkcs12) in case of truststore of keystore type."));
		META.put(PROP_KS_PATH, new PropertyMD().setCategory(ksCat).
				setDescription("The keystore path in case of truststore of keystore type."));

		META.put(PROP_OPENSSL_DIR, new PropertyMD("/etc/grid-security/certificates").setPath().setCategory(opensslCat).
				setDescription("Directory to be used for opeenssl truststore."));
		META.put(PROP_OPENSSL_NEW_STORE_FORMAT, new PropertyMD("false").setCategory(opensslCat).
				setDescription("In case of openssl truststore, specifies whether the trust store is in openssl 1.0.0+ format (true) or older openssl 0.x format (false)"));

		META.put(PROP_DIRECTORY_LOCATIONS, new PropertyMD().setList(false).setUpdateable().setCategory(dirCat).
				setDescription("List of CA certificates locations. Can contain URLs, local files and wildcard expressions."));
		META.put(PROP_DIRECTORY_ENCODING, new PropertyMD(Encoding.PEM).setCategory(dirCat).
				setDescription("For directory truststore controls whether certificates are encoded "
						+ "in PEM or DER. Note that the PEM file can contain arbitrary number "
						+ "of concatenated, PEM-encoded certificates."));
		META.put(PROP_DIRECTORY_CONNECTION_TIMEOUT, new PropertyMD("15").setCategory(dirCat).
				setDescription("Connection timeout for fetching the remote CA certificates in seconds."));
		META.put(PROP_DIRECTORY_CACHE_PATH, new PropertyMD().setPath().setCategory(dirCat).
				setDescription("Directory where CA certificates should be cached, after downloading them from a remote source. Can be left undefined if no disk cache should be used. Note that directory should be secured, i.e. normal users should not be allowed to write to it."));
	}

	protected TruststoreType type;
	
	protected long storeUpdateInterval;
	protected String opensslDir;
	protected boolean opensslNewStoreFormat;
	protected Encoding directoryEncoding;
	protected List<String> directoryLocations;
	protected int caConnectionTimeout;
	protected String caDiskCache;
	
	protected String ksPath;
	protected String ksType;
	protected PasswordCallback passwordCallback;

	/**
	 * Simple constructor: logging is turned on and standard properties prefix is used.
	 * @param properties properties object to read configuration from
	 * @throws IOException 
	 * @throws ConfigurationException whenever configuration is wrong and validator can not be instantiated.
	 * @throws KeyStoreException 
	 */
	public TrustedIssuersProperties(Properties properties, 
			Collection<? extends StoreUpdateListener> initialListeners) 
				throws ConfigurationException
	{
		this(properties, initialListeners, null, DEFAULT_PREFIX);
	}

	/**
	 * Simple constructor: logging is turned on and standard properties prefix is used.
	 * @param properties properties object to read configuration from
	 * @throws IOException 
	 * @throws ConfigurationException whenever configuration is wrong and validator can not be instantiated.
	 * @throws KeyStoreException 
	 */
	public TrustedIssuersProperties(Properties properties, 
			Collection<? extends StoreUpdateListener> initialListeners, PasswordCallback callback) 
				throws ConfigurationException
	{
		this(properties, initialListeners, callback, DEFAULT_PREFIX);
	}

	/**
	 * Allows for setting prefix and initialization listeners
	 * @param properties properties object to read configuration from
	 * @param pfx prefix to be used for properties. Should end with '.'!
	 * @throws IOException 
	 * @throws ConfigurationException whenever configuration is wrong and validator can not be instantiated.
	 * @throws KeyStoreException 
	 */
	public TrustedIssuersProperties(Properties properties, 
			Collection<? extends StoreUpdateListener> initialListeners, String pfx) 
				throws ConfigurationException
	{
		this(properties, initialListeners, null, pfx);
	}
	
	/**
	 * Allows for setting prefix, callback and initialization listeners
	 * @param properties properties object to read configuration from
	 * @param pfx prefix to be used for properties. Should end with '.'!
	 * @throws IOException 
	 * @throws ConfigurationException whenever configuration is wrong and validator can not be instantiated.
	 * @throws KeyStoreException 
	 */
	public TrustedIssuersProperties(Properties properties, 
			Collection<? extends StoreUpdateListener> initialListeners, PasswordCallback callback, String pfx) 
				throws ConfigurationException
	{
		this(META, log, properties, initialListeners, callback, pfx);
	}

	/**
	 * Use for extensions
	 * @param META
	 * @param log
	 * @param properties
	 * @param initialListeners
	 * @param callback
	 * @param pfx
	 * @throws ConfigurationException
	 */
	protected TrustedIssuersProperties(Map<String, PropertyMD> META, Logger log, Properties properties, 
			Collection<? extends StoreUpdateListener> initialListeners, PasswordCallback callback, String pfx) 
				throws ConfigurationException
	{
		super(pfx, properties, META, log);
		this.initialListeners = initialListeners;
		this.passwordCallback = callback;
		createValidatorSafe();
		addPropertyChangeListener(new PropertyChangeListenerImpl());
	}
	
	/**
	 * @return a configured validator. 
	 */
	public X509CertChainValidatorExt getValidator()
	{
		if (type.equals(TruststoreType.keystore))
		{
			return ksValidator;
		} else if (type.equals(TruststoreType.openssl))
		{
			return opensslValidator;
		} else if (type.equals(TruststoreType.directory))
		{
			return directoryValidator;
		}
		throw new RuntimeException("BUG: not all truststore types are handled in the code");
	}

	/**
	 * Checks properties and tries to update the underlying validator whenever possible.
	 * Only few options can be modified at runtime.
	 * @throws ConfigurationException 
	 */
	protected void update(String property) throws ConfigurationException
	{
		if (property.equals(PROP_UPDATE))
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
		}
		
		if (opensslValidator != null)
			return;
		
		if (ksValidator != null)
			return;
		
		if (property.startsWith(PROP_DIRECTORY_LOCATIONS))
		{
			List<String> newDirectoryLocations = getListOfValues(PROP_DIRECTORY_LOCATIONS);
			if (!newDirectoryLocations.equals(directoryLocations))
			{
				directoryValidator.setTruststorePaths(newDirectoryLocations);
				directoryLocations = newDirectoryLocations;
				log.info("Updated " + prefix+PROP_DIRECTORY_LOCATIONS);
			}
		}
	}
	
	protected String[] getUpdateableProperties()
	{
		return UPDATEABLE_PROPS;
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
	
	protected void createValidator() throws ConfigurationException,
			KeyStoreException, IOException
	{
		type = getEnumValue(PROP_TYPE, TruststoreType.class);
		storeUpdateInterval = getLongValue(PROP_UPDATE);
		
		if (type.equals(TruststoreType.keystore))
		{
			ksValidator = getKeystoreValidator();
		} else if (type.equals(TruststoreType.openssl))
		{
			opensslValidator = getOpensslValidator();
		} else if (type.equals(TruststoreType.directory))
		{
			directoryValidator = getDirectoryValidator();
		}
	}

	
	protected DirectoryCertChainValidator getDirectoryValidator() 
			throws ConfigurationException, KeyStoreException, IOException
	{
		directoryLocations = getListOfValues(PROP_DIRECTORY_LOCATIONS);
		directoryEncoding = getEnumValue(PROP_DIRECTORY_ENCODING, Encoding.class);
		caConnectionTimeout = getIntValue(PROP_DIRECTORY_CONNECTION_TIMEOUT);
		caDiskCache = getFileValueAsString(PROP_DIRECTORY_CACHE_PATH, true);
		
		ValidatorParamsExt params = getValidatorParamsExt();
		return new DirectoryCertChainValidator(directoryLocations, directoryEncoding, 
			storeUpdateInterval*1000, caConnectionTimeout*1000, caDiskCache, params);
	}

	protected OpensslCertChainValidator getOpensslValidator() throws ConfigurationException
	{
		opensslDir = getFileValueAsString(PROP_OPENSSL_DIR, true);
		opensslNewStoreFormat = getBooleanValue(PROP_OPENSSL_NEW_STORE_FORMAT);
		
		RevocationParameters revocationSettings = new RevocationParameters(CrlCheckingMode.IGNORE, 
				getOCSPParameters());
		ValidatorParams params = new ValidatorParams(revocationSettings, 
			ProxySupport.DENY, initialListeners);
		return new OpensslCertChainValidator(opensslDir, opensslNewStoreFormat, 
				NamespaceCheckingMode.IGNORE, storeUpdateInterval*1000,	params);
	}

	protected KeystoreCertChainValidator getKeystoreValidator() 
			throws ConfigurationException, KeyStoreException, IOException
	{
		ksPath = getValue(PROP_KS_PATH);
		if (ksPath == null)
			throw new ConfigurationException("Keystore path must be set, property: " + 
					prefix + PROP_KS_PATH);

		File ks = new File(ksPath);
		if (!ks.exists() || !ks.canRead() || !ks.isFile())
			throw new ConfigurationException("Keystore specified in the property " + 
					prefix + PROP_KS_PATH + " must be an EXISTING, READABLE file: " + 
					ksPath);

		boolean preferCallback = passwordCallback != null && passwordCallback.ignoreProperties();
		char[] ksPassword = null;
		if (!preferCallback)
		{
			String pass = getValue(PROP_KS_PASSWORD);
			ksPassword = pass == null ? null : pass.toCharArray();
		}
		if (ksPassword == null && passwordCallback != null)
		{
			ksPassword = passwordCallback.getPassword("truststore", ksPath);
		}
		if (ksPassword == null)
			throw new ConfigurationException("Keystore password must be set, property: " + 
					prefix + PROP_KS_PASSWORD);
		ksType = getValue(PROP_KS_TYPE);
		if (ksType == null)
			autodetectKeystoreType(ksPassword);
		
		ValidatorParamsExt params = getValidatorParamsExt();
		return new KeystoreCertChainValidator(ksPath, ksPassword, 
			ksType, storeUpdateInterval*1000, params);
	}	
	
	protected ValidatorParamsExt getValidatorParamsExt()
	{
		RevocationParametersExt revParams = new RevocationParametersExt(CrlCheckingMode.IGNORE, 
				new CRLParameters(), getOCSPParameters());
		return new ValidatorParamsExt(revParams, ProxySupport.DENY, initialListeners);
	}
	
	protected OCSPParametes getOCSPParameters()
	{
		return new OCSPParametes(OCSPCheckingMode.IGNORE);
	}
	
	private void autodetectKeystoreType(char[] ksPassword) throws ConfigurationException
	{
		try
		{
			ksType = KeystoreCredential.autodetectType(ksPath, ksPassword);
		} catch (Exception e)
		{
			e.printStackTrace();
			throw new ConfigurationException("Truststore type is not " +
					"set in the property " + prefix + PROP_KS_TYPE + 
					" and its autodetection failed. Try to set it and also " +
					"review password and location - most probably those are wrong.");
		}
	}

	/**
	 * This class is used to update configuration of validators when properties are changed.
	 * Properties reloading or setting must be triggered from outside this class.
	 * @author K. Benedyczak
	 */
	private class PropertyChangeListenerImpl implements PropertyChangeListener 
	{
		@Override
		public String[] getInterestingProperties()
		{
			return getUpdateableProperties();
		}

		@Override
		public void propertyChanged(String propertyKey)
		{
			update(propertyKey);
		}
	}
	
	public TrustedIssuersProperties clone()
	{
		TrustedIssuersProperties ret = new TrustedIssuersProperties(properties, initialListeners, passwordCallback, prefix);
		super.cloneTo(ret);
		return ret;
	}
}
