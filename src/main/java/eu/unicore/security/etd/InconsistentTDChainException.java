/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Jun 2, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

/**
 * Thrown when opertaion is invoked on trust delegation chain which was specified
 * in terms of DNs, while operation tries to add assertion in terms of certificates
 * or vice versa. 
 * @author K. Benedyczak
 */
public class InconsistentTDChainException extends Exception
{
	private static final long serialVersionUID = 1L;
}
