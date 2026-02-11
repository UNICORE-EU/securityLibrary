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
