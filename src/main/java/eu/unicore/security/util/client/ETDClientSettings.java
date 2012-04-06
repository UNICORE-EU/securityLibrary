/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 17-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.util.client;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import eu.unicore.security.etd.DelegationRestrictions;
import eu.unicore.security.etd.TrustDelegation;

/**
 * Contains all settings which are required to set up the delegation and user assertions. 
 *  
 * @author golbi
 *
 */
public class ETDClientSettings implements Cloneable
{
	private String requestedUser;
	private Map<String,String[]> requestedAttributes = new HashMap<String, String[]>();
	private X500Principal receiver;
	private boolean extendTrustDelegation;
	private List<TrustDelegation> trustDelegationTokens;
	private X509Certificate[] issuerCertificateChain;
	private DelegationRestrictions delegationRestrictions = new DelegationRestrictions(null, null, 10);
	private Integer relativeDelegationValidityDays = 30;
	
	/**
	 * SAML attribute name for transporting attribute requests from client to server 
	 */
	public static final String SAML_ATTRIBUTE_REQUEST_NAMEFORMAT = "urn:unicore:subject-requested-attribute";

	/**
	 * Sets the user under whose identity you want the request to be invoked.
	 * <p>
	 * Note that if you don't use this method but add trust delegations then the requested user 
	 * will be implicitly set to the initial issuer (custodian) of the ETD chain.
	 * This method it therefore useful when the client doesn't send ETD tokens but has anyway
	 * rights to invoke operations on the requestedUser behalf (i.e. because of possession of 
	 * a trusted agent role in the XUUDB/UVOS).
	 * @param requested user's DN 
	 */
	public void setRequestedUser(String requestedUserDN)
	{
		this.requestedUser = requestedUserDN;
	}

	/**
	 * 
	 * @return the identity of the requested user as set by the setRequestedUser method.
	 * Note that this method won't return the implicit user which is taken from the ETD chain
	 * if the setRequestedUser was NOT called.
	 */
	public String getRequestedUser()
	{
		return requestedUser;
	}

	/**
	 * For outgoing calls, get extra attributes which are stored in User assertions.
	 * Those attributes are used to express various preferences regarding the request.
	 * <br/>
	 * This will return a modifiable map, never <code>null</code>.
	 * To add an attribute request to a client call, do<br/>
	 * <pre>
	 * sec.getRequestedUserAttributes().put("XLOGIN", "test");
	 * </pre>
	 */
	public Map<String,String[]> getRequestedUserAttributes2()
	{
		return requestedAttributes;
	}

	
	
	
	/**
	 * for calls that need to issue trust delegations,
	 * return the {@link X500Principal} of the receiver
	 */
	public X500Principal getReceiver()
	{
		return receiver;
	}
	
	/**
	 * for calls that need to issue trust delegations,
	 * set the {@link X500Principal} of the receiver
	 */
	public void setReceiver(X500Principal receiver)
	{
		this.receiver = receiver;
	}

	/**
	 * for outgoing calls, determines if the client side shall generate 
	 * a new TD (possibly extending an existing chain) for the receiver 
	 * as set with setReceiver method.
	 */
	public boolean isExtendTrustDelegation()
	{
		return extendTrustDelegation;
	}
	
	/**
	 * select whether trust delegation shall be extended
	 */
	public void setExtendTrustDelegation(boolean value)
	{
		this.extendTrustDelegation = value;
	}
	
	/**
	 * get trust delegations to be passed on or extended
	 */
	public List<TrustDelegation> getTrustDelegationTokens()
	{
		return trustDelegationTokens;
	}
	
	/**
	 * set trust delegations to be passed on or extended
	 * @param tdTokens
	 */
	public void setTrustDelegationTokens(List<TrustDelegation> tdTokens)
	{
		this.trustDelegationTokens = tdTokens;
	}
	
	/**
	 * the full X509 certificate chain of the issuer (the local user/client).
	 */
	public X509Certificate[] getIssuerCertificateChain()
	{
		return issuerCertificateChain;
	}

	/**
	 * the full X509 certificate chain of the issuer (the local user/client).
	 */
	public void setIssuerCertificateChain(X509Certificate[] certChain)
	{
		this.issuerCertificateChain = certChain;
	}
	
	/**
	 * Sets delegation restrictions
	 * @param delegationRestrictions
	 */
	public void setDelegationRestrictions(DelegationRestrictions delegationRestrictions)
	{
		this.delegationRestrictions = delegationRestrictions;
	}

	/**
	 * Gets delegation restrictions
	 * @return
	 */
	public DelegationRestrictions getDelegationRestrictions()
	{
		return delegationRestrictions;
	}

	/**
	 * If relative validity is set then time constraints in delegation are computed 
	 * just before delegation creation. Beginning of validity is set to 1 hour 
	 * before the current time (to accommodate possible lack of clocks synchronization)
	 * and end of validity is set to the specified number of days from the time
	 * of assertion creation.
	 * <br>
	 * By default this option is used, and is set to one month.
	 * @param relativeDelegationValidityDays use null value to disable this feature
	 */
	public void setRelativeDelegationValidityDays(
			Integer relativeDelegationValidityDays)
	{
		this.relativeDelegationValidityDays = relativeDelegationValidityDays;
	}

	/**
	 * 
	 * @return number of days for which the newly created delegation is valid.
	 */
	public Integer getRelativeDelegationValidityDays()
	{
		return relativeDelegationValidityDays;
	}
	
	/**
	 * Convenience method, allows for setting up ETD with one invocation. This is useful
	 * for creation of an initial assertion with default settings.
	 * @param requestedUserDN
	 * @param delegationReceiver
	 */
	public void initializeSimple(X500Principal delegationReceiver,	IAuthenticationConfiguration properties)
	{
		String requestedUserDN = properties.getCertificateChain()[0].getSubjectX500Principal().getName();
		setRequestedUser(requestedUserDN);
		setReceiver(delegationReceiver);
		setExtendTrustDelegation(true);
		setIssuerCertificateChain(properties.getCertificateChain());
	}
	
	public ETDClientSettings clone()
	{
		ETDClientSettings copy = new ETDClientSettings();
		copy.extendTrustDelegation = extendTrustDelegation;
		if (issuerCertificateChain != null)
			copy.issuerCertificateChain = issuerCertificateChain.clone();
		copy.receiver = receiver;
		copy.requestedAttributes.putAll(requestedAttributes);
		copy.requestedUser = requestedUser;
		if (trustDelegationTokens != null)
		{
			copy.trustDelegationTokens = new ArrayList<TrustDelegation>();
			copy.trustDelegationTokens.addAll(trustDelegationTokens);
		}
		copy.relativeDelegationValidityDays = relativeDelegationValidityDays;
		copy.delegationRestrictions = delegationRestrictions.clone();
		return copy;
	}
}
