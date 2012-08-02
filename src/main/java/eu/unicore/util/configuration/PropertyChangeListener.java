/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.configuration;

/**
 * Implementations are notified about property value changes. 
 * @author K. Benedyczak
 */
public interface PropertyChangeListener
{
	/**
	 * @return array with base property names, for which change notifications should be produced or
	 * null if all property changes should result in notification. If null is passed, then it may happen
	 * that notification will be raised even when no property value was changed but only the file was modified.
	 */
	public String[] getInterestingProperties();
	
	/**
	 * Invoked when a property change was detected.
	 * @param propertyKey null if {@link #getInterestingProperties()} returns null. Otherwise it is one of the
	 * property keys returned by {@link #getInterestingProperties()}.
	 */
	public void propertyChanged(String propertyKey);
}
