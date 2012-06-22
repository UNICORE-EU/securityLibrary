/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

import eu.unicore.security.util.PropertyMD.Type;

/**
 * Generates Asciidoc table with properties info
 * @author K. Benedyczak
 */
public class AsciidocFormatter implements HelpFormatter
{
	@Override
	public String format(String pfx, Map<String, PropertyMD> metadata)
	{
		SortedSet<String> keys = new TreeSet<String>(metadata.keySet());
		if (keys.size() == 0)
			return "";
		StringBuilder ret = new StringBuilder();
		ret.append("[width=\"100%\",cols=\"<m,<,<,<\",frame=\"topbot\",options=\"header\"]\n");
		ret.append("|=====================================================================\n");
		ret.append("|Property name |Type |Default value / mandatory |Description \n");
		for (String key: keys)
		{
			PropertyMD md = metadata.get(key);

			ret.append("|" + pfx + key);
			if (md.getType() == Type.LIST)
				ret.append(md.numericalListKeys() ? "<NUMBER>" : "*");
			if (md.canHaveSubkeys())
				ret.append("[.*]");
			ret.append(" |");
			
			ret.append(md.getTypeDescription());
			if (md.canHaveSubkeys())
				ret.append(" _can have subkeys_");
			ret.append(" |");
			
			if (md.isMandatory())
				ret.append("_mandatory to be set_ |");
			else if (md.hasDefault())
			{
				if (md.getDefault().equals(""))
					ret.append("_empty string_ |");
				else
					ret.append("`" + md.getDefault() +"` |");
			} else
				ret.append("- |");
			String desc = md.getDescription();
			if (desc == null)
				desc = " ";
			ret.append(desc + " \n");
		}
		ret.append("|=====================================================================\n");
		return ret.toString();
	}
	
	public static void main(String... args) throws Exception
	{
		if (args.length < 2)
			throw new IllegalArgumentException("Args: <target directory> <triple as one string: class|target file|prefix where prefix is optional>");
		for (int i=1; i<args.length; i++)
		{
			String[] genArgs = args[i].split("\\|");
			if (genArgs.length < 2 || genArgs.length > 3)
				throw new IllegalArgumentException("Args: <target directory> <triple as one string: class|target file|prefix where prefix is optional>");
			String prefix = genArgs.length == 3 ? genArgs[2] : null;
			processFile(args[0], genArgs[0], genArgs[1], prefix);
		}
	}
	
	private static Field getField(Class<?> clazz, String defaultName, 
			Class<? extends Annotation> annotation, Class<?> desiredType) throws Exception
	{
		Field field = null;
		Field[] fields = clazz.getDeclaredFields();
		for (Field f: fields)
		{
			if (f.getAnnotation(annotation) != null)
			{
				field = f;
				break;
			}
		}
		if (field == null)
			field = clazz.getDeclaredField(defaultName);
		if (!Modifier.isStatic(field.getModifiers()))
			throw new IllegalArgumentException("The field " + field.getName() + " of the class " + 
					clazz.getName() + " is not static");
		if (!desiredType.isAssignableFrom(field.getType()))
			throw new IllegalArgumentException("The field " + field.getName() + " of the class " +
					clazz.getName() + " is not of " + desiredType.getName() + " type");
		field.setAccessible(true);
		return field;
	}
	
	public static void processFile(String folder, String clazzName, String destination, String prefix) throws Exception
	{
		System.out.println("Generating from: " + clazzName + " to " + destination + " prefix: " + prefix);
		ClassLoader loader = AsciidocFormatter.class.getClassLoader();
		Class<?> clazz = loader.loadClass(clazzName);
		
		
		Field fMeta = getField(clazz, "META", DocumentationReferenceMeta.class, Map.class);
		if (prefix == null)
		{
			Field fPrefix = getField(clazz, "DEFAULT_PREFIX", DocumentationReferencePrefix.class, String.class);
			prefix = (String) fPrefix.get(null);
		}
		
		@SuppressWarnings("unchecked")
		Map<String, PropertyMD> meta = (Map<String, PropertyMD>) fMeta.get(null);

		AsciidocFormatter formatter = new AsciidocFormatter();
		String result = formatter.format(prefix, meta);
		BufferedWriter w = new BufferedWriter(new FileWriter(new File(folder, destination)));
		w.write(result);
		w.close();
	}
}
