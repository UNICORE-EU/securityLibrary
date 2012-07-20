/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.canl;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
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
import eu.emi.security.authn.x509.OCSPResponder;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.RevocationParameters.RevocationCheckingOrder;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.CRLParameters;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.impl.DirectoryCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.RevocationParametersExt;
import eu.emi.security.authn.x509.impl.ValidatorParams;
import eu.emi.security.authn.x509.impl.ValidatorParamsExt;
import eu.unicore.util.Log;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.configuration.PropertiesHelper;
import eu.unicore.util.configuration.PropertyMD;



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
	
	public enum TruststoreType {keystore, openssl, directory};
	//common for all
	public static final String PROP_TYPE = "type";

	public static final String PROP_UPDATE = "updateInterval";
	public static final String PROP_PROXY_SUPPORT = "allowProxy";
	public static final String PROP_CRL_MODE = "crlMode";
	public static final String PROP_OCSP_MODE = "ocspMode";
	public static final String PROP_OCSP_TIMEOUT = "ocspTimeout";
	public static final String PROP_OCSP_CACHE_TTL = "ocspCacheTtl";
	public static final String PROP_OCSP_DISK_CACHE = "ocspDiskCache";
	public static final String PROP_OCSP_LOCAL_RESPONDERS = "ocspLocalResponders.";
	public static final String PROP_REVOCATION_ORDER = "revocationOrder";
	public static final String PROP_REVOCATION_USE_ALL = "revocationUseAll";
	
	//these are common for keystore and directory trust stores
	public static final String PROP_CRL_LOCATIONS = "crlLocations.";
	public static final String PROP_CRL_UPDATE = "crlUpdateInterval";
	public static final String PROP_CRL_CONNECTION_TIMEOUT = "crlConnectionTimeout";
	public static final String PROP_CRL_CACHE_PATH = "crlDiskCachePath";
	
	//the rest is store dependent
	public static final String PROP_KS_PATH = "keystorePath";
	public static final String PROP_KS_PASSWORD = "keystorePassword";
	public static final String PROP_KS_TYPE = "keystoreFormat";

	public static final String PROP_OPENSSL_DIR = "opensslPath";
	public static final String PROP_OPENSSL_NS_MODE = "opensslNsMode";
	
	public static final String PROP_DIRECTORY_LOCATIONS = "directoryLocations.";
	public static final String PROP_DIRECTORY_ENCODING = "directoryEncoding";
	public static final String PROP_DIRECTORY_CONNECTION_TIMEOUT = "directoryConnectionTimeout";
	public static final String PROP_DIRECTORY_CACHE_PATH = "directoryDiskCachePath";
	
	private Collection<? extends StoreUpdateListener> initialListeners;
	private OpensslCertChainValidator opensslValidator = null;
	private DirectoryCertChainValidator directoryValidator = null;
	private KeystoreCertChainValidator ksValidator = null;
		
	public final static Map<String, PropertyMD> META = new HashMap<String, PropertyMD>();
	static 
	{
		META.put(PROP_TYPE, new PropertyMD().setEnum(TruststoreType.directory).
				setMandatory().setDescription("The truststore type."));
		META.put(PROP_PROXY_SUPPORT, new PropertyMD(ProxySupport.ALLOW).
				setDescription("Controls whether proxy certificates are supported."));
		META.put(PROP_UPDATE, new PropertyMD("600").setLong().
				setDescription("How often the truststore should be reloaded, in seconds. Set to negative value to disable refreshing at runtime."));

		META.put(PROP_KS_PASSWORD, new PropertyMD().setSecret().setCategory("Keystore").
				setDescription("The password of the keystore type truststore."));
		META.put(PROP_KS_TYPE, new PropertyMD().setCategory("Keystore").
				setDescription("The keystore type (jks, pkcs12) in case of truststore of keystore type."));
		META.put(PROP_KS_PATH, new PropertyMD().setCategory("Keystore").
				setDescription("The keystore path in case of truststore of keystore type."));

		META.put(PROP_OPENSSL_NS_MODE, new PropertyMD(NamespaceCheckingMode.EUGRIDPMA_GLOBUS).setCategory("Openssl").
				setDescription("In case of openssl truststore, controls which (and in which order) namespace checking rules should be applied. The 'REQUIRE' settings will cause that all configured namespace definitions files must be present for each trusted CA certificate (otherwise checking will fail). The 'AND' settings will cause to check both existing namespace files. Otherwise the first found is checked (in the order defined by the property)."));
		META.put(PROP_OPENSSL_DIR, new PropertyMD("/etc/grid-security/certificates").setPath().setCategory("Openssl").
				setDescription("Directory to be used for opeenssl truststore."));

		META.put(PROP_DIRECTORY_LOCATIONS, new PropertyMD().setList(false).setCategory("Directory").
				setDescription("List of CA certificates locations. Can contain URLs, local files and wildcard expressions."));
		META.put(PROP_DIRECTORY_ENCODING, new PropertyMD(Encoding.PEM).setCategory("Directory").
				setDescription("For directory truststore controls whether certificates are encoded in PEM or DER."));
		META.put(PROP_DIRECTORY_CONNECTION_TIMEOUT, new PropertyMD("15").setCategory("Directory").
				setDescription("Connection timeout for fetching the remote CA certificates in seconds."));
		META.put(PROP_DIRECTORY_CACHE_PATH, new PropertyMD().setPath().setCategory("Directory").
				setDescription("Directory where CA certificates should be cached, after downloading them from a remote source. Can be left undefined if no disk cache should be used. Note that directory should be secured, i.e. normal users should not be allowed to write to it."));

		META.put(PROP_REVOCATION_ORDER, new PropertyMD(RevocationCheckingOrder.OCSP_CRL).setCategory("Revocation").
				setDescription("Controls overal revocation sources order"));
		META.put(PROP_REVOCATION_USE_ALL, new PropertyMD("false").setCategory("Revocation").
				setDescription("Controls whether all defined revocation sources should be always checked, even if the first one already confirmed that a checked certificate is not revoked."));
		META.put(PROP_CRL_MODE, new PropertyMD(CrlCheckingMode.IF_VALID).setCategory("Revocation").
				setDescription("General CRL handling mode. The IF_VALID setting turns on CRL checking only in case the CRL is present."));
		META.put(PROP_CRL_UPDATE, new PropertyMD("600").setLong().setCategory("Revocation").
				setDescription("How often CRLs should be updated, in seconds. Set to negative value to disable refreshing at runtime."));
		META.put(PROP_CRL_CONNECTION_TIMEOUT, new PropertyMD("15").setCategory("Revocation").
				setDescription("Connection timeout for fetching the remote CRLs in seconds (not used for Openssl truststores)."));
		META.put(PROP_CRL_CACHE_PATH, new PropertyMD().setPath().setCategory("Revocation").
				setDescription("Directory where CRLs should be cached, after downloading them from " +
						"remote source. Can be left undefined if no disk cache should be used. Note that directory should be secured, i.e. normal users should not be allowed to write to it. Not used for Openssl truststores."));
		META.put(PROP_CRL_LOCATIONS, new PropertyMD().setList(false).setCategory("Revocation").
				setDescription("List of CRLs locations. Can contain URLs, local files and wildcard expressions. Not used for Openssl truststores."));
		META.put(PROP_OCSP_MODE, new PropertyMD(OCSPCheckingMode.IF_AVAILABLE).setCategory("Revocation").
				setDescription("General OCSP ckecking mode. REQUIRE should not be used unless it is guaranteed that for all certificates an OCSP responder is defined."));
		META.put(PROP_OCSP_LOCAL_RESPONDERS, new PropertyMD().setList(true).setCategory("Revocation").
				setDescription("Optional list of local OCSP responders"));
		META.put(PROP_OCSP_TIMEOUT, new PropertyMD(""+OCSPParametes.DEFAULT_TIMEOUT).setCategory("Revocation").
				setDescription("Timeout for OCSP connections in miliseconds."));
		META.put(PROP_OCSP_CACHE_TTL, new PropertyMD(""+OCSPParametes.DEFAULT_CACHE).setCategory("Revocation").
				setDescription("For how long the OCSP responses should be locally cached in seconds (this is a maximum value, responses won't be cached after expiration)"));
		META.put(PROP_OCSP_DISK_CACHE, new PropertyMD().setPath().setCategory("Revocation").
				setDescription("If this property is defined then OCSP responses will be cached on disk in the defined folder."));
	}

	private TruststoreType type;
	
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
		super(pfx, properties, META, log);
		this.initialListeners = initialListeners;
		createValidatorSafe();
	}
	
	/**
	 * @return a configured validator. 
	 */
	public X509CertChainValidator getValidator()
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
		
		long newCrlUpdateInterval = getLongValue(PROP_CRL_UPDATE);
		if (newCrlUpdateInterval != crlUpdateInterval)
		{
			if (directoryValidator != null)
				directoryValidator.setCRLUpdateInterval(newCrlUpdateInterval*1000);
			if (ksValidator != null)
				ksValidator.setCRLUpdateInterval(newCrlUpdateInterval*1000);
			crlUpdateInterval = newCrlUpdateInterval;
			log.info("Updated " + prefix+PROP_CRL_UPDATE + " value to " + crlUpdateInterval);
		}
		
		List<String> newCrlLocations = getListOfValues(PROP_CRL_LOCATIONS);
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
		
		List<String> newDirectoryLocations = getListOfValues(PROP_DIRECTORY_LOCATIONS);
		if (!newDirectoryLocations.equals(directoryLocations))
		{
			directoryValidator.setTruststorePaths(newDirectoryLocations);
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
		type = getEnumValue(PROP_TYPE, TruststoreType.class);
		storeUpdateInterval = getLongValue(PROP_UPDATE);
		
		crlMode = getEnumValue(PROP_CRL_MODE, CrlCheckingMode.class);
		proxySupport = getEnumValue(PROP_PROXY_SUPPORT, ProxySupport.class);
		
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

	
	
	private DirectoryCertChainValidator getDirectoryValidator() 
			throws ConfigurationException, KeyStoreException, IOException
	{
		setCrlSettings();
		directoryLocations = getListOfValues(PROP_DIRECTORY_LOCATIONS);
		directoryEncoding = getEnumValue(PROP_DIRECTORY_ENCODING, Encoding.class);
		caConnectionTimeout = getIntValue(PROP_DIRECTORY_CONNECTION_TIMEOUT);
		caDiskCache = getFileValueAsString(PROP_DIRECTORY_CACHE_PATH, true);
		
		ValidatorParamsExt params = getValidatorParamsExt();
		return new DirectoryCertChainValidator(directoryLocations, directoryEncoding, 
			storeUpdateInterval*1000, caConnectionTimeout*1000, caDiskCache, params);
	}

	private OpensslCertChainValidator getOpensslValidator() throws ConfigurationException
	{
		nsMode = getEnumValue(PROP_OPENSSL_NS_MODE, NamespaceCheckingMode.class);
		opensslDir = getFileValueAsString(PROP_OPENSSL_DIR, true);
		RevocationCheckingOrder order = getEnumValue(PROP_REVOCATION_ORDER, RevocationCheckingOrder.class);
		boolean useAll = getBooleanValue(PROP_REVOCATION_USE_ALL);

		RevocationParameters revocationSettings = new RevocationParameters(crlMode, getOCSPParameters(),
				useAll, order);
		ValidatorParams params = new ValidatorParams(revocationSettings, 
			proxySupport, initialListeners);
		return new OpensslCertChainValidator(opensslDir, nsMode, storeUpdateInterval*1000, 
			params);
	}

	private KeystoreCertChainValidator getKeystoreValidator() 
			throws ConfigurationException, KeyStoreException, IOException
	{
		setCrlSettings();
		ksPath = getValue(PROP_KS_PATH);
		if (ksPath == null)
			throw new ConfigurationException("Keystore path must be set, property: " + 
					prefix + PROP_KS_PATH);

		File ks = new File(ksPath);
		if (!ks.exists() || !ks.canRead() || !ks.isFile())
			throw new ConfigurationException("Keystore specified in the property " + 
					prefix + PROP_KS_PATH + " must be an EXISTING, READABLE file: " + 
					ksPath);

		String pass = getValue(PROP_KS_PASSWORD);
		if (pass == null)
			throw new ConfigurationException("Keystore password must be set, property: " + 
					prefix + PROP_KS_PASSWORD);
		ksPassword = pass.toCharArray();
		
		ksType = getValue(PROP_KS_TYPE);
		if (ksType == null)
			autodetectKeystoreType();
		
		ValidatorParamsExt params = getValidatorParamsExt();
		return new KeystoreCertChainValidator(ksPath, ksPassword, 
			ksType, storeUpdateInterval*1000, params);
	}	
	
	private void setCrlSettings() throws ConfigurationException
	{
		crlUpdateInterval = getLongValue(PROP_CRL_UPDATE);
		crlConnectionTimeout = getIntValue(PROP_CRL_CONNECTION_TIMEOUT);
		crlDiskCache = getFileValueAsString(PROP_CRL_CACHE_PATH, true);
		crlLocations = getListOfValues(PROP_CRL_LOCATIONS);
	}
	
	private ValidatorParamsExt getValidatorParamsExt()
	{
		CRLParameters crlParameters = new CRLParameters(crlLocations, crlUpdateInterval*1000, 
			crlConnectionTimeout, crlDiskCache);
		RevocationCheckingOrder order = getEnumValue(PROP_REVOCATION_ORDER, RevocationCheckingOrder.class);
		boolean useAll = getBooleanValue(PROP_REVOCATION_USE_ALL);
		RevocationParametersExt revParams = new RevocationParametersExt(crlMode, 
			crlParameters, getOCSPParameters(), useAll, order);
		return new ValidatorParamsExt(revParams, proxySupport, initialListeners);
	}
	
	private OCSPParametes getOCSPParameters()
	{
		OCSPCheckingMode checkingMode = getEnumValue(PROP_OCSP_MODE, OCSPCheckingMode.class);
		int connectTimeout = getIntValue(PROP_OCSP_TIMEOUT);
		int cacheTtl = getIntValue(PROP_OCSP_CACHE_TTL);
		String diskCachePath = getFileValueAsString(PROP_OCSP_DISK_CACHE, true);
		
		List<String> localRespondersCfg = getListOfValues(PROP_OCSP_LOCAL_RESPONDERS);
		OCSPResponder[] localResponders = new OCSPResponder[localRespondersCfg.size()];
		for (int i=0; i<localResponders.length; i++)
		{
			String cfg = localRespondersCfg.get(i);
			cfg = cfg.trim();
			String[] arr = cfg.split("[ ]+");
			BufferedInputStream is = null;
			if (arr.length != 2)
				throw new ConfigurationException("Local responder's number " + (i+1) + 
						" configuration is invalid, must be: " +
						"'<responderURL> <responderPemCertificatePath>'");
			try
			{
				is = new BufferedInputStream(new FileInputStream(arr[1]));
				X509Certificate cert = CertificateUtils.loadCertificate(is, Encoding.PEM);
				localResponders[i] = new OCSPResponder(new URL(arr[0]), cert);			
			} catch (FileNotFoundException e)
			{
				throw new ConfigurationException("Local responder's number " + (i+1) + 
						" certificate can not be loaded, file " + arr[1] + " not found.", e);
			} catch (MalformedURLException e)
			{
				throw new ConfigurationException("Local responder's URL " + arr[0] + " is malformed: " 
						+ e.getMessage(), e);
			} catch (IOException e)
			{
				throw new ConfigurationException("Local responder's number " + (i+1) + 
						" certificate can not be loaded: " + e.getMessage(), e);
			} finally
			{
				if (is != null)
					try
					{
						is.close();
					} catch (IOException e)
					{
						//ignored
					}
			}
		}
		
		
		return new OCSPParametes(checkingMode, localResponders, connectTimeout, true, false, 
				cacheTtl, diskCachePath);
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
}
