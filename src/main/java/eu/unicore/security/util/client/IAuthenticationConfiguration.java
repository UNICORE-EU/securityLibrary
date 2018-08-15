/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util.client;

import eu.unicore.util.httpclient.IClientConfiguration;
import eu.unicore.util.httpclient.IPlainClientConfiguration;

/**
 * @deprecated Use {@link IClientConfiguration} instead, but please note that it is not one-to-one mapping.
 * {@link IClientConfiguration} provides more information and in some cases the {@link IPlainClientConfiguration}
 * can be used instead.
 * @author K. Benedyczak
 */
@Deprecated
public interface IAuthenticationConfiguration extends IClientConfiguration
{
}
