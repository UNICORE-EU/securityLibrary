package eu.unicore.security.canl;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.logging.log4j.Logger;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.OCSPResponder;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.RevocationParameters.RevocationCheckingOrder;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.impl.CRLParameters;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.impl.DirectoryCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.RevocationParametersExt;
import eu.emi.security.authn.x509.impl.ValidatorParams;
import eu.emi.security.authn.x509.impl.ValidatorParamsExt;
import eu.unicore.util.Log;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.configuration.PropertyMD;
import eu.unicore.util.configuration.PropertyMD.DocumentationCategory;



/**
 * This class allows for setting up trust management (e.g. used to verify
 * certificates of SSL peers) from Java properties.
 * <p>
 * The class maintains a reference to the created validator and can try to update
 * its configuration upon request.
 * <p>
 * It is implemented as an extension of {@link TrustedIssuersProperties} and adds support for configuring Namespaces,
 * proxy support and revocation settings.
 * 
 * @author K. Benedyczak
 */
public class TruststoreProperties extends TrustedIssuersProperties
{
	private static final Logger log = Log.getLogger(Log.CONFIGURATION, TruststoreProperties.class);

	public static final String DEFAULT_PREFIX = "truststore.";

	//common for all
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

	public static final String PROP_OPENSSL_NS_MODE = "opensslNsMode";

	private final static String[] UPDATEABLE_PROPS = {PROP_UPDATE, PROP_CRL_UPDATE, 
			PROP_DIRECTORY_LOCATIONS, PROP_CRL_LOCATIONS};

	public final static Map<String, PropertyMD> META = new HashMap<>();
	static 
	{
		DocumentationCategory opensslCat = new DocumentationCategory("Openssl type settings", "3");
		DocumentationCategory revCat = new DocumentationCategory("Revocation settings", "4");
		
		META.putAll(TrustedIssuersProperties.META);
		
		META.put(PROP_PROXY_SUPPORT, new PropertyMD(ProxySupport.ALLOW).
				setDescription("Controls whether proxy certificates are supported."));

		META.put(PROP_OPENSSL_NS_MODE, new PropertyMD(NamespaceCheckingMode.EUGRIDPMA_GLOBUS).setCategory(opensslCat).
				setDescription("In case of openssl truststore, controls which (and in which order) namespace checking rules should be applied. The 'REQUIRE' settings will cause that all configured namespace definitions files must be present for each trusted CA certificate (otherwise checking will fail). The 'AND' settings will cause to check both existing namespace files. Otherwise the first found is checked (in the order defined by the property)."));		

		META.put(PROP_REVOCATION_ORDER, new PropertyMD(RevocationCheckingOrder.OCSP_CRL).setCategory(revCat).
				setDescription("Controls overal revocation sources order"));
		META.put(PROP_REVOCATION_USE_ALL, new PropertyMD("false").setCategory(revCat).
				setDescription("Controls whether all defined revocation sources should be always checked, even if the first one already confirmed that a checked certificate is not revoked."));
		META.put(PROP_CRL_MODE, new PropertyMD(CrlCheckingMode.IF_VALID).setCategory(revCat).
				setDescription("General CRL handling mode. The IF_VALID setting turns on CRL checking only in case the CRL is present."));
		META.put(PROP_CRL_UPDATE, new PropertyMD("600").setLong().setUpdateable().setCategory(revCat).
				setDescription("How often CRLs should be updated, in seconds. Set to negative value to disable refreshing at runtime."));
		META.put(PROP_CRL_CONNECTION_TIMEOUT, new PropertyMD("15").setCategory(revCat).
				setDescription("Connection timeout for fetching the remote CRLs in seconds (not used for Openssl truststores)."));
		META.put(PROP_CRL_CACHE_PATH, new PropertyMD().setPath().setCategory(revCat).
				setDescription("Directory where CRLs should be cached, after downloading them from " +
						"remote source. Can be left undefined if no disk cache should be used. Note that directory should be secured, i.e. normal users should not be allowed to write to it. Not used for Openssl truststores."));
		META.put(PROP_CRL_LOCATIONS, new PropertyMD().setList(false).setUpdateable().setCategory(revCat).
				setDescription("List of CRLs locations. Can contain URLs, local files and wildcard expressions. Not used for Openssl truststores."));
		META.put(PROP_OCSP_MODE, new PropertyMD(OCSPCheckingMode.IF_AVAILABLE).setCategory(revCat).
				setDescription("General OCSP ckecking mode. REQUIRE should not be used unless it is guaranteed that for all certificates an OCSP responder is defined."));
		META.put(PROP_OCSP_LOCAL_RESPONDERS, new PropertyMD().setList(true).setCategory(revCat).
				setDescription("Optional list of local OCSP responders"));
		META.put(PROP_OCSP_TIMEOUT, new PropertyMD(""+OCSPParametes.DEFAULT_TIMEOUT).setCategory(revCat).
				setDescription("Timeout for OCSP connections in miliseconds."));
		META.put(PROP_OCSP_CACHE_TTL, new PropertyMD(""+OCSPParametes.DEFAULT_CACHE).setCategory(revCat).
				setDescription("For how long the OCSP responses should be locally cached in seconds (this is a maximum value, responses won't be cached after expiration)"));
		META.put(PROP_OCSP_DISK_CACHE, new PropertyMD().setPath().setCategory(revCat).
				setDescription("If this property is defined then OCSP responses will be cached on disk in the defined folder."));
	}

	private ProxySupport proxySupport;
	private CrlCheckingMode crlMode;
	private NamespaceCheckingMode nsMode;
	private long crlUpdateInterval;
	private int crlConnectionTimeout;
	private String crlDiskCache;
	private List<String> crlLocations;

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
		this(properties, initialListeners, null, DEFAULT_PREFIX);
	}

	/**
	 * Simple constructor: logging is turned on and standard properties prefix is used.
	 * @param properties properties object to read configuration from
	 * @throws IOException 
	 * @throws ConfigurationException whenever configuration is wrong and validator can not be instantiated.
	 * @throws KeyStoreException 
	 */
	public TruststoreProperties(Properties properties, 
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
	public TruststoreProperties(Properties properties, 
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
	public TruststoreProperties(Properties properties, 
			Collection<? extends StoreUpdateListener> initialListeners, PasswordCallback callback, String pfx) 
				throws ConfigurationException
	{
		super(META, log, properties, initialListeners, callback, pfx);
	}

	/**
	 * Checks properties and tries to update the underlying validator whenever possible.
	 * Only few options can be modified at runtime.
	 * @throws ConfigurationException 
	 */
	protected void update(String property) throws ConfigurationException
	{
		super.update(property);
		if (opensslValidator != null)
			return;

		if (property.equals(PROP_CRL_UPDATE))
		{
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
		}

		if (property.startsWith(PROP_CRL_LOCATIONS))
		{
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
		}
	}

	protected String[] getUpdateableProperties()
	{
		return UPDATEABLE_PROPS;
	}

	protected void createValidator() throws ConfigurationException,
			GeneralSecurityException, IOException
	{
		crlMode = getEnumValue(PROP_CRL_MODE, CrlCheckingMode.class);
		proxySupport = getEnumValue(PROP_PROXY_SUPPORT, ProxySupport.class);
		super.createValidator();
	}

	protected DirectoryCertChainValidator getDirectoryValidator() 
			throws ConfigurationException, KeyStoreException, IOException
	{
		setCrlSettings();
		return super.getDirectoryValidator();
	}

	protected OpensslCertChainValidator getOpensslValidator() throws ConfigurationException
	{
		nsMode = getEnumValue(PROP_OPENSSL_NS_MODE, NamespaceCheckingMode.class);
		opensslDir = getFileValueAsString(PROP_OPENSSL_DIR, true);
		opensslNewStoreFormat = getBooleanValue(PROP_OPENSSL_NEW_STORE_FORMAT);
		
		RevocationCheckingOrder order = getEnumValue(PROP_REVOCATION_ORDER, RevocationCheckingOrder.class);
		boolean useAll = getBooleanValue(PROP_REVOCATION_USE_ALL);

		RevocationParameters revocationSettings = new RevocationParameters(crlMode, getOCSPParameters(),
				useAll, order);
		ValidatorParams params = new ValidatorParams(revocationSettings, 
			proxySupport, initialListeners);
		return new OpensslCertChainValidator(opensslDir, opensslNewStoreFormat, nsMode, 
				storeUpdateInterval*1000, params);
	}

	protected KeystoreCertChainValidator getKeystoreValidator() 
			throws ConfigurationException, KeyStoreException, IOException
	{
		setCrlSettings();
		return super.getKeystoreValidator();
	}

	protected void setCrlSettings() throws ConfigurationException
	{
		crlUpdateInterval = getLongValue(PROP_CRL_UPDATE);
		crlConnectionTimeout = getIntValue(PROP_CRL_CONNECTION_TIMEOUT);
		crlDiskCache = getFileValueAsString(PROP_CRL_CACHE_PATH, true);
		crlLocations = getListOfValues(PROP_CRL_LOCATIONS);
	}

	protected ValidatorParamsExt getValidatorParamsExt()
	{
		CRLParameters crlParameters = new CRLParameters(crlLocations, crlUpdateInterval*1000, 
			crlConnectionTimeout, crlDiskCache);
		RevocationCheckingOrder order = getEnumValue(PROP_REVOCATION_ORDER, RevocationCheckingOrder.class);
		boolean useAll = getBooleanValue(PROP_REVOCATION_USE_ALL);
		RevocationParametersExt revParams = new RevocationParametersExt(crlMode, 
			crlParameters, getOCSPParameters(), useAll, order);
		return new ValidatorParamsExt(revParams, proxySupport, initialListeners);
	}

	protected OCSPParametes getOCSPParameters()
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
			if (arr.length != 2)
				throw new ConfigurationException("Local responder's number " + (i+1) + 
						" configuration is invalid, must be: " +
						"'<responderURL> <responderPemCertificatePath>'");
			try(BufferedInputStream is = new BufferedInputStream(new FileInputStream(arr[1])))
			{
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
			}
		}
		return new OCSPParametes(checkingMode, localResponders, connectTimeout, true, false, 
				cacheTtl, diskCachePath);
	}
	
	public TruststoreProperties clone()
	{
		TruststoreProperties ret = new TruststoreProperties(properties, initialListeners, passwordCallback, prefix);
		super.cloneTo(ret);
		return ret;
	}
}
