/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.configuration;

import java.util.Arrays;


/**
 * Provides an optional metadata for properties retrieved using {@link PropertiesHelper}.
 * Uses the fluent style and shortened syntax
 * @author K. Benedyczak
 */
public class PropertyMD
{
	public enum Type {INT, LONG, FLOAT, BOOLEAN, STRING, PATH, ENUM, LIST}
	
	private boolean secret;
	private String defaultValue;
	private boolean hasDefault;
	private boolean mandatory;
	private boolean canHaveSubkeys = false;
	private boolean numericalListKeys = false;
	private boolean updateable = false;
	private String description;
	private String category;
	private long min = Integer.MIN_VALUE;
	private long max = Integer.MAX_VALUE;
	private double minFloat = Double.MIN_VALUE;
	private double maxFloat = Double.MAX_VALUE;
	private Type type = Type.STRING; 
	private Enum<?> enumTypeInstance;

	/**
	 * Creates a non-secret property, with a default value 
	 * (it can't become mandatory property as we have a default).
	 * The property type will be guessed in that order: int, long, float, boolean. If the default 
	 * value can not be mapped to any of those types, the type will be String. The type can be later
	 * freely changed, but default value must be of the type set. 
	 * @param defaultValue
	 */
	public PropertyMD(String defaultValue) {
		this.defaultValue = defaultValue;
		this.hasDefault = true;
		if (isInt(defaultValue))
			this.type = Type.INT;
		else if (isLong(defaultValue))
			this.type = Type.LONG;
		else if (isFloat(defaultValue))
			this.type = Type.FLOAT;
		else if (isBoolean(defaultValue))
			this.type = Type.BOOLEAN;
		else
			this.type = Type.STRING;
	}

	/**
	 * Creates a property of enum type with a desired enum default value.
	 * @param defaultValue
	 */
	public <T extends Enum<T>> PropertyMD(T defaultValue) {
		enumTypeInstance = defaultValue;
		this.hasDefault = true;
		this.defaultValue = defaultValue.name();
		this.type = Type.ENUM;
	}
	
	/**
	 * public, non mandatory property without a default value of String type.
	 */
	public PropertyMD() {
	}

	public boolean isSecret() {
		return secret;
	}
	public PropertyMD setSecret() {
		this.secret = true;
		return this;
	}
	public String getDefault() {
		return defaultValue;
	}
	public PropertyMD setDefault(String defaultValue) {
		if (isMandatory())
			throw new IllegalStateException("A property can not have a default " +
					"value and be mandatory at the same time");
		if (type == Type.BOOLEAN && !isBoolean(defaultValue))
			throw new IllegalStateException("A property defualt type must be valid value of its type: boolean");
		if (type == Type.INT && !isInt(defaultValue))
			throw new IllegalStateException("A property defualt type must be valid value of its type: int");
		if (type == Type.LONG && !isLong(defaultValue))
			throw new IllegalStateException("A property defualt type must be valid value of its type: long");

		this.defaultValue = defaultValue;
		this.hasDefault = true;
		return this;
	}
	public boolean isMandatory() {
		return mandatory;
	}
	public PropertyMD setMandatory() {
		if (hasDefault())
			throw new IllegalStateException("A property can not have a default " +
					"value and be mandatory at the same time");
		this.mandatory = true;
		return this;
	}
	public PropertyMD setDescription(String description) {
		this.description = description;
		return this;
	}
	public boolean hasDefault() {
		return hasDefault;
	}
	
	public boolean isUpdateable() {
		return updateable;
	}
	public PropertyMD setUpdateable(boolean updateable) {
		this.updateable = updateable;
		return this;
	}
	
	public PropertyMD setBounds(long min, long max) {
		if (type != Type.INT && type != Type.LONG)
			throw new IllegalStateException("Integer bounds can be only set for int or long property");
		this.min = min;
		this.max = max;
		return this;
	}
	public PropertyMD setBounds(double min, double max) {
		if (type != Type.FLOAT)
			throw new IllegalStateException("Floating point bounds can be only set for Floating point property");
		this.minFloat = min;
		this.maxFloat = max;
		return this;
	}
	public PropertyMD setPositive() {
		this.min = 1;
		this.minFloat = 0.001;
		return this;
	}
	public PropertyMD setNonNegative() {
		this.min = 0;
		this.minFloat = 0.0;
		return this;
	}
	public PropertyMD setMin(long min) {
		if (type != Type.INT && type != Type.LONG)
			throw new IllegalStateException("Integer bounds can be only set for int or long property");
		this.min = min;
		return this;
	}
	public PropertyMD setMax(long max) {
		if (type != Type.INT && type != Type.LONG)
			throw new IllegalStateException("Integer bounds can be only set for int or long property");
		this.max = max;
		return this;
	}
	public PropertyMD setMin(double min) {
		if (type != Type.FLOAT)
			throw new IllegalStateException("Floating point bounds can be only set for Floating point property");
		this.minFloat = min;
		return this;
	}
	public PropertyMD setMax(double max) {
		if (type != Type.FLOAT)
			throw new IllegalStateException("Floating point bounds can be only set for Floating point property");
		this.maxFloat = max;
		return this;
	}
	public PropertyMD setLong() {
		this.type = Type.LONG;
		this.max = Long.MAX_VALUE;
		this.min = Long.MIN_VALUE;
		return this;
	}
	/**
	 * Sets enum type. Note that the value passed as argument doesn't matter, it
	 * must be only of the proper enum, which shall make an enum type of the property.
	 * @param defaultValue
	 * @return
	 */
	public <T extends Enum<T>> PropertyMD setEnum(T defaultValue) {
		enumTypeInstance = defaultValue;
		this.type = Type.ENUM;
		return this;
	}
	public PropertyMD setInt() {
		this.type = Type.INT;
		this.max = Integer.MAX_VALUE;
		this.min = Integer.MIN_VALUE;
		return this;
	}
	public PropertyMD setFloat() {
		this.type = Type.FLOAT;
		return this;
	}
	public PropertyMD setBoolean() {
		this.type = Type.BOOLEAN;
		return this;
	}
	public PropertyMD setPath() {
		this.type = Type.PATH;
		return this;
	}
	public PropertyMD setList(boolean numericalKeys) {
		this.type = Type.LIST;
		this.numericalListKeys = numericalKeys;
		return this;
	}
	public boolean numericalListKeys() {
		return numericalListKeys;
	}
	
	
	public boolean canHaveSubkeys() {
		return canHaveSubkeys;
	}
	public PropertyMD setCanHaveSubkeys()
	{
		this.canHaveSubkeys = true;
		return this;
	}

	public String getDescription() {
		return description;
	}
	public long getMin() {
		return min;
	}
	public long getMax() {
		return max;
	}
	public double getMinFloat() {
		return minFloat;
	}
	public double getMaxFloat() {
		return maxFloat;
	}
	public Type getType() {
		return type;
	}
	public Enum<?> getEnumTypeInstance() {
		return enumTypeInstance;
	}
	
	
	protected boolean isBoolean(String val) {
		if (val == null)
			return false;
	       	if (val.equalsIgnoreCase("true") || val.equalsIgnoreCase("yes"))
	       		return true;
	       	if (val.equalsIgnoreCase("false") || val.equalsIgnoreCase("no"))
	       		return true;
	       	return false;
	}

	protected boolean isLong(String val) {
		try
		{
			Long.parseLong(val);
			return true;
		} catch (NumberFormatException e)
		{
			return false;
		}
	}

	protected boolean isInt(String val) {
		try
		{
			Integer.parseInt(val);
			return true;
		} catch (NumberFormatException e)
		{
			return false;
		}
	}

	protected boolean isFloat(String val) {
		try
		{
			Double.parseDouble(val);
			return true;
		} catch (NumberFormatException e)
		{
			return false;
		}
	}
	
	/**
	 * Returns human friendly description of the property type
	 * @return
	 */
	public String getTypeDescription() {
		switch(type)
		{
		case STRING:
			return "string";
		case BOOLEAN:
			return "[true, false]";
		case ENUM:
			Object[] allValues = (enumTypeInstance.getDeclaringClass()).getEnumConstants();
			return Arrays.toString(allValues);
		case INT:
		case LONG:
			boolean hasMin = false;
			if (min != Integer.MIN_VALUE && min != Long.MIN_VALUE)
				hasMin = true;
			boolean hasMax = false;
			if (max != Integer.MAX_VALUE && max != Long.MAX_VALUE)
				hasMax = true;
			if (!hasMin && !hasMax)
				return "integer number";
			if (hasMin && hasMax)
				return "integer [" + min + " -- " + max + "]";
			if (hasMin)
				return "integer > " + min;
			if (hasMax)
				return "integer < " + max;
		case PATH:
			return "filesystem path";
		case LIST:
			return "list of properties with a common prefix";
		case FLOAT:
			boolean hasMinF = false;
			if (minFloat != Double.MIN_VALUE && minFloat != Double.MIN_VALUE)
				hasMinF = true;
			boolean hasMaxF = false;
			if (maxFloat != Double.MAX_VALUE && maxFloat != Double.MAX_VALUE)
				hasMaxF = true;
			if (!hasMinF && !hasMaxF)
				return "floating point number";
			if (hasMinF && hasMaxF)
				return "floating [" + minFloat + " -- " + maxFloat + "]";
			if (hasMinF)
				return "floating > " + minFloat;
			if (hasMaxF)
				return "floating < " + maxFloat;
		default:
			return "UNKNOWN";
		}
	}

	/**
	 * @return the category
	 */
	public String getCategory() {
		return category;
	}

	/**
	 * @param optional property category
	 */
	public PropertyMD setCategory(String category) {
		this.category = category;
		return this;
	}
}
