/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;


/**
 * Wrapping class of the PropertiesHelper, adding file backing (with reloading support).
 * 
 * @author K. Benedyczak
 */
public class FilePropertiesHelper extends PropertiesHelper
{
	protected File file;
	protected long lastAccess;
	

	public FilePropertiesHelper(String prefix, String file,
			Map<String, PropertyMD> meta, Logger log)
			throws ConfigurationException, IOException
	{
		this(prefix, new File(file), meta, log);
	}

	public FilePropertiesHelper(String prefix, File file,
			Map<String, PropertyMD> meta, Logger log)
			throws ConfigurationException, IOException
	{
		super(prefix, load(file), meta, log);
		this.file = file;
		lastAccess = file.lastModified();
	}

	public synchronized void reload() throws IOException, ConfigurationException
	{
		setProperties(load(file));
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





