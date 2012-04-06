/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;


/**
 * Wrapping class of the PropertiesHelper, adding file backing (with reloading support).
 * 
 * @author K. Benedyczak
 */
public class FilePropertiesHelper
{
	protected PropertiesHelper wrapped;
	protected File file;
	protected long lastAccess;
	

	public FilePropertiesHelper(PropertiesHelper base, String file) throws ConfigurationException
	{
		this(base, new File(file));
	}

	public FilePropertiesHelper(PropertiesHelper base, File file) throws ConfigurationException
	{
		this.file = file;
		this.wrapped = base;
	}

	public synchronized PropertiesHelper reload() throws IOException, ConfigurationException
	{
		if (file == null)
			throw new IllegalStateException("Reloading is only possible if the object " +
					"is backed up by a file");
		
		wrapped.setProperties(load(file));
		return wrapped;
	}
	
	public PropertiesHelper get()
	{
		return wrapped;
	}
	
	public File getFile()
	{
		return file;
	}

	private boolean hasChanged()
	{
		long fileMod = file.lastModified();
		boolean ret = (lastAccess==0 || lastAccess<fileMod);
		lastAccess=fileMod;
		return ret;
	}
	
	public boolean reloadIfChanged() throws IOException, ConfigurationException
	{
		if (hasChanged())
		{
			reload();
			return true;
		}
		return false;
	}

	
	public static Properties load(String file) throws IOException 
	{
		return load(new File(file));
	}
	
	public static Properties load(File file) throws IOException 
	{
		BufferedInputStream is = new BufferedInputStream(new FileInputStream(file));
		Properties properties = new Properties();
		try
		{
			properties.load(is);
		} catch (Exception e)
		{
			throw new Error("Can not load properties file " + file + ": " + e.getMessage(), e);
		} finally 
		{ 
			is.close();
		}
		return properties;
	}
}





