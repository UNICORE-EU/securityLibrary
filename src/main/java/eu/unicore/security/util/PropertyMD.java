/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

/**
 * Provides an optional metadata for properties retrieved using {@link PropertiesHelper}.
 * Uses the fluent style and shortened syntax
 * @author K. Benedyczak
 */
public class PropertyMD 
{
	private boolean secret;
	private String defaultValue;
	private boolean hasDefault;
	private boolean mandatory;
	private String description;
	private long min = Integer.MIN_VALUE;
	private long max = Integer.MAX_VALUE;

	/**
	 * public property with a default value (non mandatory to be set as we have default)
	 * @param defaultValue
	 */
	public PropertyMD(String defaultValue) {
		this.defaultValue = defaultValue;
		this.hasDefault = true;
	}
	
	/**
	 * public, non mandatory property without a default value
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
	public String getDefaultValue() {
		return defaultValue;
	}
	public PropertyMD setDefaultValue(String defaultValue) {
		if (isMandatory())
			throw new IllegalStateException("A property can not have a default " +
					"value and be mandatory at the same time");
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
	public String getDescription() {
		return description;
	}
	public PropertyMD setDescription(String description) {
		this.description = description;
		return this;
	}
	public boolean hasDefault() {
		return hasDefault;
	}
	public PropertyMD setBounds(long min, long max) {
		this.min = min;
		this.max = max;
		return this;
	}
	public PropertyMD setPositive() {
		this.min = 1;
		return this;
	}
	public PropertyMD setNonNegative() {
		this.min = 0;
		return this;
	}
	public PropertyMD setMin(long min) {
		this.min = min;
		return this;
	}
	public PropertyMD setMax(long max) {
		this.max = max;
		return this;
	}
	public PropertyMD setLong() {
		this.max = Long.MAX_VALUE;
		this.min = Long.MIN_VALUE;
		return this;
	}
	public long getMin() {
		return min;
	}
	public long getMax() {
		return max;
	}
}
