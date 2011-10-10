/*
 * Copyright (c) 2010 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 2011-02-11
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.util;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Enumeration;

/**
 * Checks if provided truststore/keystore settings are valid. 
 */
public class KeystoreChecker
{
	public static String findAlias(KeyStore ks) throws KeyStoreException
	{
		Enumeration<String> aliases = ks.aliases();
		while (aliases.hasMoreElements())
		{
			String a = aliases.nextElement();
			if (ks.isKeyEntry(a))
				return a;
		}
		return null;
	}
	
	public static void validateTruststore(String file, String password, String type) throws Exception 
	{
		if (password == null || password.equals(""))
			throw new Exception("Truststore password can not be empty. " +
					"Unfortunately many libraries does not allow for this. " +
			"Please set in on your keystore and in your configuration.");

		KeystoreUtil.loadTruststore(file, password, type);
	}
	
	public static void validateKeystore(String file, String password, String keyPassword, 
			String type, String alias) throws Exception 
	{
		if (password == null || password.equals(""))
			throw new Exception("Keystore password can not be empty. " +
					"Unfortunately many libraries does not allow for this. " +
			"Please set in on your keystore and in your configuration.");

		KeyStore ks = KeystoreUtil.loadKeyStore(file, password, type);
		if (alias == null)
			alias = findAlias(ks);
		if (alias == null)
			throw new KeyStoreException("There is no key entry in the keystore");
		if (!ks.containsAlias(alias))
			throw new KeyStoreException("Alias " + alias + " is not present in the keystore");
		if (!ks.isKeyEntry(alias))
			throw new KeyStoreException("Alias " + alias + " is not a key entry in the keystore");
		ks.getKey(alias, keyPassword.toCharArray());
	}
}
