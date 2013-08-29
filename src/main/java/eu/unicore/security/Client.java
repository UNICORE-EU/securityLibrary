/*********************************************************************************
 * Copyright (c) 2006 Forschungszentrum Juelich GmbH 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * (1) Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the disclaimer at the end. Redistributions in
 * binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * 
 * (2) Neither the name of Forschungszentrum Juelich GmbH nor the names of its 
 * contributors may be used to endorse or promote products derived from this 
 * software without specific prior written permission.
 * 
 * DISCLAIMER
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *********************************************************************************/
 

package eu.unicore.security;

import java.io.Serializable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import eu.emi.security.authn.x509.impl.X500NameUtils;

/**
 * Describes the entity that is performing an operation on the server side.
 * Wraps low level security material which was used to authenticate the client
 * (including attributes which can be used for authorization) and values chosen
 * during the client incarnation, like local xlogin, security role, VOs or groups. 
 *  
 * @author schuller
 * @author golbi
 */
public class Client implements Serializable {
	
	/**
	 * Defines a type of client.
	 * @author K. Benedyczak
	 */
	public static enum Type {
		/**
		 * The object represents an external client who was somehow 
		 * authenticated.
		 */
		AUTHENTICATED, 
		/**
		 * The object represents an external client who was not authenticated, 
		 * i.e. we don't know who it is
		 */
		ANONYMOUS,
		/**
		 * The object is associated with an operation invoked by the local server
		 * code on its own behalf 
		 */
		LOCAL
	}; 
	
	private static final long serialVersionUID=1L;
	
	//for some use cases, credentials are stored in the client object
	public static final String ATTRIBUTE_CREDENTIALS_USERNAME="creds.username";
	public static final String ATTRIBUTE_CREDENTIALS_PASSWORD="creds.password";
	
	//for storing the email address in the attributes
	public static final String ATTRIBUTE_USER_EMAIL="user.email";
	
	/**
	 * Fake DN used to identify an anonymous client. It is used just not to return null.
	 */
	public static final String ANONYMOUS_CLIENT_DN = "CN=ANONYMOUS,O=UNKNOWN,OU=UNKNOWN";

	/**
	 * Fake DN used to identify a local client.
	 */
	public static final String LOCAL_CLIENT_DN = "CN=Local_call";

	
	//the token by which a client is identified
	private SecurityTokens secTokens;
	
	//what kind of client
	private Type type; 
	
	//the (set of) possible unix login name(s) and groups optionally with the preferred one
	private Xlogin xlogin;

	//the role of the client
	private Role role;
	
	//list of VOs the user is a member of
	private String[] vos;
	
	//VO under which the request is performed, may be null
	private String vo;
	
	private Queue queue;
	
	
	//all attributes that were established by attribute sources.
	private SubjectAttributesHolder subjectAttributes;
	
	//additional attributes may contain things relevant on the target system 
	//such as license keys, ... In most cases subjectAttributes are what you need.
	private final Map<String,Serializable> extraAttributes;
	
	/**
	 * Constructs an anonymous Client. Setters must be used to fully configure
	 * the Client.
	 */
	public Client() {
		setAnonymousClient();
		extraAttributes = new HashMap<String,Serializable>();
		setSubjectAttributes(new SubjectAttributesHolder());
		xlogin = new Xlogin();
		role = new Role();
		vos = new String[0];
		queue = new Queue();
	}
	
	public String toString() {
		StringBuilder cInfo = new StringBuilder();
		
		cInfo.append("Name: ");
		cInfo.append(X500NameUtils.getReadableForm(getDistinguishedName()));
		cInfo.append("\nXlogin: ");
		cInfo.append(getXlogin());
		cInfo.append("\nRole: ");
		cInfo.append(getRole());
		if (queue.getValidQueues().length > 0) {
			cInfo.append("\nQueues: ");
			cInfo.append(queue);
		}
		if (vos.length > 0) {
			cInfo.append("\nVOs: ");
			cInfo.append(Arrays.toString(vos));
		}
		if (vo != null) {
			cInfo.append("\nSelected VO: ").append(vo);
		}
		if (secTokens != null)
		{
			cInfo.append("\nSecurity tokens: ");
			cInfo.append(secTokens);
		}	
		return cInfo.toString(); 
	}


	/**
	 * @return type of this client
	 */
	public Type getType() {
		return type;
	}

	/**
	 * Makes this client ANONYMOUS 
	 */
	public void setAnonymousClient() {
		this.type = Type.ANONYMOUS;
		this.secTokens = null;
	}

	/**
	 * Makes this client LOCAL 
	 */
	public void setLocalClient() {
		this.type = Type.LOCAL;
		this.secTokens = null;
	}

	/**
	 * Sets the type of this client basing on SecurityTokens - 
	 * it can be AUTHENTICATED or ANONYMOUS. 
	 * @param secTokens security tokens established during authentication 
	 */
	public void setAuthenticatedClient(SecurityTokens secTokens) {
		this.secTokens = secTokens;
		if (secTokens == null || secTokens.getEffectiveUserName() == null) {
			this.type = Type.ANONYMOUS;
			return;
		}
		this.type = Type.AUTHENTICATED;
	}

	/**
	 * @return Returns the {@link SecurityTokens} or null if 
	 * the client is not of AUTHENTICATED type
	 */
	public SecurityTokens getSecurityTokens() {
		return secTokens;
	}

	/**
	 * @return the client's distinguished name. For authenticated 
	 * clients it is the effective user's name. For other types of clients one 
	 * of predefined constants is returned. This method never returns null.
	 */
	public String getDistinguishedName() {
		if (type == Type.ANONYMOUS)
			return ANONYMOUS_CLIENT_DN;
		else if (type == Type.LOCAL)
			return LOCAL_CLIENT_DN;
		else
			return secTokens.getEffectiveUserName();
	}
	
	
	//****************** INCARNATION AND AUTHZ PART *******************************
	
	
	/**
	 * @return Returns the role.
	 */
	public Role getRole() {
		return role;
	}
	
	/**
	 * @param role The role to set.
	 */
	public void setRole(Role role) {
		this.role = role;
	}

	
	public Map<String, Serializable> getExtraAttributes() {
		return extraAttributes;
	}
	
	/**
	 * convenience method for getting the user's xlogin
	 * @return an {@link Xlogin}
	 */
	public Xlogin getXlogin(){
		return xlogin;
	}
	
	/**
	 * convenience method for setting the user's xlogin
	 * @return an {@link Xlogin}
	 */
	public void setXlogin(Xlogin xlogin){
		if (xlogin == null)
			throw new IllegalArgumentException("Setting null xlogin is prohibited.");
		this.xlogin=xlogin;
	}

	/**
	 * Convenience method returning the selected Xlogin name.
	 * @return
	 */
	public String getSelectedXloginName() {
		return xlogin.getUserName();
	}

	/**
	 * Convenience method setting the selected Xlogin name.
	 * @param userName
	 */
	public void setSelectedXloginName(String userName) {
		xlogin.setSelectedLogin(userName);
	}

	public String getUserEmail(){
		return (String)extraAttributes.get(ATTRIBUTE_USER_EMAIL);
	}
	
	public void setUserEmail(String email){
		if(email==null)extraAttributes.remove(ATTRIBUTE_USER_EMAIL);
		extraAttributes.put(ATTRIBUTE_USER_EMAIL,email);
	}

	public void setSubjectAttributes(SubjectAttributesHolder subjectAttributes) {
		this.subjectAttributes = subjectAttributes;
	}

	public SubjectAttributesHolder getSubjectAttributes() {
		return subjectAttributes;
	}

	public String[] getVos() {
		return vos;
	}

	public void setVos(String[] vos) {
		if (vos == null)
			throw new IllegalArgumentException("Can not set null VOs array, use empty array instead");
		this.vos = vos;
	}

	public Queue getQueue() {
		return queue;
	}

	public void setQueue(Queue queue) {
		if (queue == null)
			throw new IllegalArgumentException("Can not set null Queue object, use empty Queue instead");
		this.queue = queue;
	}
	
	/**
	 * @return the selected VO or null if request is not VO bound
	 */
	public String getVo() {
		return vo;
	}

	/**
	 * @param vo the vo to set. Must be one of VOs set for this object
	 * @throws IllegalArgumentException if argument is not in all client's VOs.
	 */
	public void setVo(String vo) {
		for (String v: vos)
			if (v.equals(vo))
			{
				this.vo = vo;
				return;
			}
		throw new IllegalArgumentException("The selected VO '" + vo + 
				"' is not one of the VOs the client is memeber of");
	}
}
