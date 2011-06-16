/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 29-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security;

import java.io.Serializable;

/**
 * Holds info about queues the client can use. This information is collected from attribute sources
 * The selected queue is also stored.
 * @author golbi
 */
public class Queue implements Serializable
{
	
	private static final long serialVersionUID=1L;
	
	private String selectedQueue;
	private String []validQueues;

	public Queue(String[] validQueues)
	{
		this.validQueues = validQueues;
		if (validQueues == null)
			this.validQueues = new String[0];
	}
	
	public Queue()
	{
		this.validQueues = new String[0];
	}

	public String getSelectedQueue()
	{
		if (selectedQueue == null && validQueues.length > 0)
			return validQueues[0];
		return selectedQueue;
	}

	public void setSelectedQueue(String selectedQueue)
	{
		for (String valid: validQueues)
			if (valid.equals(selectedQueue))
			{
				this.selectedQueue = selectedQueue;
				return;
			}
		throw new SecurityException("Requested queue <"+selectedQueue+"> is not available.");
	}

	public String[] getValidQueues()
	{
		return validQueues;
	}

	public void setValidQueues(String[] validQueues)
	{
		this.validQueues = validQueues;
	}
	
	public boolean isSelectedQueueSet()
	{
		return selectedQueue != null;
	}
	
	public String toString()
	{
		if (getValidQueues().length == 0)
			return "";
		
		StringBuilder cInfo = new StringBuilder(); 
		cInfo.append("[");
		for (int i=0; i<getValidQueues().length-1; i++) {
			cInfo.append(getValidQueues()[i]);
			cInfo.append(":");
		}
		cInfo.append(getValidQueues()[getValidQueues().length-1]);
		
		if (getValidQueues().length > 1) {
			cInfo.append(", selected=");
			cInfo.append(getSelectedQueue());
		}
		cInfo.append("]");
		return cInfo.toString();
	}
}
