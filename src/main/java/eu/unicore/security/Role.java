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

/**
 * A Role defines the rights a {@link Client} has
 *
 * @author schuller
 */
public class Role implements Serializable {
		
	private static final long serialVersionUID = 1L;

	/**
	 * role attribute value: anonymous
	 */
	public static final String ROLE_ANONYMOUS="anonymous";

	
	private String name,description;
	private String[] validRoles;
	
	/**
	 * Creates an anonymous role
	 */
	public Role() {
		this.name = ROLE_ANONYMOUS;
		this.description = "No role information available";
	}
	
	/**
	 * Creates a specific role, which is used as the only one valid.
	 * @param n
	 * @param d
	 */
	public Role(String n, String d){
		this.name=n;
		this.description=d;
		validRoles = new String[] {name};
	}

	/**
	 * Creates a specific role, with a list of other valid roles.
	 * The specified role must be one of valid roles.
	 * @param n
	 * @param d
	 */
	public Role(String n, String d, String[] valid){
		this.name=n;
		this.description=d;
		this.validRoles = valid;
		if (!isValid(n))
			throw new IllegalArgumentException("Selected role must be one of valid roles");
	}

	/**
	 * Creates with a list of other valid roles, the first one is selected
	 */
	public Role(String[] valid){
		this.name=valid[0];
		this.description="";
		this.validRoles = valid;
	}
	
	public String getName() {
		if(validRoles==null)return ROLE_ANONYMOUS;
		return (name!=null) ? name:validRoles[0];	
	}
	
	public String toString() {
		return name + ": " + description;
	}
	
	public String[] getValidRoles() {
		return validRoles;
	}

	/**
	 * @return Returns the description.
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * @param description The description to set.
	 */
	public void setDescription(String description) {
		if (description == null)
			throw new IllegalArgumentException("Role description can not be null");
		this.description = description;
	}

	/**
	 * @param name The name to set, must be valid
	 */
	public void setName(String name) {
		if (!isValid(name))
			throw new IllegalArgumentException("Selected role must be one of valid roles");
		this.name = name;
	}
	
	/**
	 * @param preferredRole - the preferred role
	 * @return true if this object contains the preferred one
	 */
	public boolean isValid(String preferredRole) {
		//null is always valid as a preferred - when set it means that first 
		//role on the list should be used.
		if (preferredRole == null) 
			return true;
		if (validRoles == null)
			return false;
		for(String s: validRoles){
			if(preferredRole.equals(s))
				return true;
		}
		return false;
	}

}
