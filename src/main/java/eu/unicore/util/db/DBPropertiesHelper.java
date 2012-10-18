/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.db;

import java.sql.Driver;
import java.util.HashMap;
import java.util.Map;

import eu.unicore.util.configuration.DocumentationReferencePrefix;
import eu.unicore.util.configuration.PropertiesHelper;
import eu.unicore.util.configuration.PropertyMD;
import eu.unicore.util.configuration.PropertyMD.DocumentationCategory;

/**
 * Base class for implementations using database access. It is not a classic, ready to use {@link PropertiesHelper}
 * extension as in few cases the DB properties are dependent on the service: supported DB variants and defaults.
 * <p>
 * The dialect property is optional. It is useful in case when different SQL versions are provided (e.g. for 
 * MyBatis) to choose one. 
 *
 * @author K. Benedyczak
 */
public abstract class DBPropertiesHelper
{
	@DocumentationReferencePrefix
	public static final String PREFIX = "db.";

	public final static String DIALECT = PREFIX+"dialect";
	public final static String USER = PREFIX+"username";
	public final static String PASSWORD = PREFIX+"password";
	public final static String URL = PREFIX+"jdbcUrl";
	public final static String DRIVER = PREFIX+"driver";
	public final static DocumentationCategory dbCategory = new DocumentationCategory("Database");
	
	/**
	 * Returns a fully initialized database metadata, ready to be included in PropertyHelper extension.
	 * None of the properties is marked as mandatory. Example usage:
	 * <p>
	 * <pre>
	 * public enum DBTypes {h2, mysql};
	 * ...
	 * META.putAll(DBPropertiesHelper.getMetadata(Driver.class, "jdbc:h2:data/myDb", DBTypes.h2));
	 * </pre>
	 * @param defaultDriver default JDBC driver or null if no default should be set
	 * @param defaultUrl default JDBC URL or null if no default should be set 
	 * @param defaultDialect default value of an arbitrary enum specifying allowed variants of SQL dialects.
	 * If is null then dialects property won't be included in returned metadata. 
	 * @return
	 */
	public static <T extends Enum<T>> Map<String, PropertyMD> getMetadata(Class<? extends Driver> defaultDriver, 
			String defaultUrl, T defaultDialect)
	{
		Map<String, PropertyMD> ret = new HashMap<String, PropertyMD>();
		if (defaultDialect != null)
			ret.put(DIALECT, new PropertyMD(defaultDialect).setCategory(dbCategory).
				setDescription("Database SQL dialect. Must match the selected driver, however " +
						"sometimes more then one driver can be available for a dialect."));
		ret.put(DRIVER, new PropertyMD(defaultDriver, Driver.class).setCategory(dbCategory).
				setDescription("Database driver class name. This property is optional - if not set, " +
						"then a default driver for the chosen database type is used."));
		ret.put(URL, new PropertyMD(defaultUrl).setCategory(dbCategory).
				setDescription("Database JDBC URL."));
		ret.put(USER, new PropertyMD("sa").setCategory(dbCategory).
				setDescription("Database username."));
		ret.put(PASSWORD, new PropertyMD("").setCategory(dbCategory).
				setDescription("Database password."));
		return ret;
	}
}
