/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security;

/**
 * Predefined operation types. This enum can be freely extended in future - PDP should adapt itself automatically.
 * @author K. Benedyczak
 */
public enum OperationType {
	/**
	 * The operation is read-only, i.e. it doesn't modify a resource state.
	 */
	read,
	
	/**
	 * The operation can modify the resource and we can assume that operations of this type 
	 * require the full access to the resource.
	 */
	modify
}
