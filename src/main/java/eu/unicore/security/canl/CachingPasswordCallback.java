/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.canl;

import java.util.HashMap;
import java.util.Map;

/**
 * This abstract class provides a commonly useful feature: passwords are cached.
 * 
 * @author K. Benedyczak
 */
public abstract class CachingPasswordCallback implements PasswordCallback
{
	private transient Map<String, char[]> cache = new HashMap<String, char[]>();
	
	@Override
	public final char[] getPassword(String protectedArtifactType, String protectedArtifactDescription)
	{
		String key = protectedArtifactType + "__||__" + protectedArtifactDescription;
		char[] cached = cache.get(key);
		if (cached != null)
			return cached;
		cached = getPasswordFromUser(protectedArtifactType, protectedArtifactDescription);
		cache.put(key, cached);
		return cached;
	}
	
	/**
	 * Implement this method to obtain the password. It is guaranteed that this method is called only once
	 * per type and description combination.
	 * @param protectedArtifactType
	 * @param protectedArtifactDescription
	 */
	protected abstract char[] getPasswordFromUser(String protectedArtifactType, String protectedArtifactDescription);
}
