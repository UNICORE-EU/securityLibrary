/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util.client;

import eu.emi.security.authn.x509.X509Credential;
import eu.unicore.security.canl.IAuthnAndTrustConfiguration;

/**
 * @deprecated Use {@link IAuthnAndTrustConfiguration} instead, but please note that it is not one-to-one mapping.
 * {@link IAuthnAndTrustConfiguration} provides more information. If only the credential information is needed 
 * then use {@link X509Credential}.
 * @author K. Benedyczak
 */
@Deprecated
public interface ISecurityConfiguration extends IAuthnAndTrustConfiguration
{

}
