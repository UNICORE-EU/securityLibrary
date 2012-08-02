/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.configuration;

import java.io.File;
import java.io.IOException;


/**
 * Wrapping of the PropertiesHelper, adding file backing (with reloading support).
 * This class is similar to {@link FilePropertiesHelper} but it is not extending the {@link PropertiesHelper}.
 * Therefore it can be used for optional file backing.
 * The class implements Runnable, so it can be directly used by some scheduler to perform 
 * checks for the updated configuration.  
 * 
 * @author K. Benedyczak
 */
public class WrappingFilePropertiesHelper implements Runnable
{
	protected File file;
	protected long lastAccess;
	protected PropertiesHelper wrapped;
	

	public WrappingFilePropertiesHelper(PropertiesHelper helper, String file)
			throws ConfigurationException, IOException
	{
		this(helper, new File(file));
	}

	public WrappingFilePropertiesHelper(PropertiesHelper helper, File file)
			throws ConfigurationException, IOException
	{
		this.file = file;
		this.wrapped = helper;
		lastAccess = file.lastModified();
	}

	public void reload() throws IOException, ConfigurationException
	{
		wrapped.setProperties(FilePropertiesHelper.load(file));
	}
	
	public File getFile()
	{
		return file;
	}

	private boolean hasChanged()
	{
		return FilePropertiesHelper.hasFileChanged(lastAccess, file);
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

	@Override
	public void run()
	{
		try
		{
			reloadIfChanged();
		} catch (ConfigurationException e)
		{
			wrapped.getLoger().warn("The reloaded configuration is invalid: " + e.getMessage(), e);
		} catch (IOException e)
		{
			wrapped.getLoger().warn("Can't re-read the configuration file " + file + 
					": " + e.getMessage(), e);
		}
	}
}





