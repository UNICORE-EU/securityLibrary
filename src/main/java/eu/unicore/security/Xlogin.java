/*********************************************************************************
 * Copyright (c) 2008 Forschungszentrum Juelich GmbH 
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


/**
 * Represents the user's remote login and group information<br/>
 * 
 * Users may have multiple xlogins/groups mapped to the same authentication
 * token, and may select one of these through the job description
 * 
 * @author schuller
 * @author golbi
 */
public class Xlogin implements Serializable{

	private static final long serialVersionUID = 1L;

	private String[] logins;
	private String selectedLogin;
	
	private String[] groups;
	private String selectedGroup;
	private String[] selectedSupplementaryGroups;
	private boolean addDefaultGroups = true;
	
	/**
	 * constructs a new Xlogin instance from the list of logins 
	 * @param logins - the logins
	 */
	public Xlogin(String[] logins){
		this.logins=logins;
	}
	
	/**
	 * constructs a new Xlogin instance from the lists of logins and groups 
	 * @param logins - the logins
	 * @param groups - the groups
	 */
	public Xlogin(String[] logins, String[] groups){
		this.logins=logins;
		this.groups=groups;
	}
	
	public Xlogin(){
	}
	
	/**
	 * sets the login that should be used. The selection is checked.
	 * 
	 * @param login - the login to use
	 * @throws AAAException - in case the selected login is not one of the allowed logins
	 */
	public void setSelectedLogin(String login)throws SecurityException{
		if(isValid(login)){
			selectedLogin=login;
		}
		else throw new SecurityException("Requested login <"+login+"> is not available.");
	}

	/**
	 * returns the default xlogin, which is either the one selected using {@link #setSelectedLogin(String)},
	 * or the first entry in the list of logins
	*/
	public String getUserName(){
		if(logins==null)return null;
		return (selectedLogin!=null) ? selectedLogin:logins[0];
	}
	
	/**
	 * @param preferredLogin - the preferred login
	 * @return true if this xlogin contains the preferred one
	 */
	public boolean isValid(String preferredLogin){
		//null is always valid as a preferred - when set it means that first 
		//login on the list should be used.
		if (preferredLogin == null) 
			return true;
		if (logins == null)
			return false;
		for(String s: logins){
			if(preferredLogin.equals(s))
				return true;
		}
		return false;
	}

	public String[] getLogins(){
		return logins;
	}
	
	/**
	 * returns the list of xlogins as ":" separated String
	 * @return the encoded list of xlogins, or an empty string if empty
	 */
	public String getEncoded(){
		return getEncodedInteranl(logins);
	}
	
	/**
	 * returns the list of groups as ":" separated String
	 * @return the encoded list of groups, or an empty string if empty
	 */
	public String getEncodedGroups(){
		return getEncodedInteranl(groups);
	}
	
	private String getEncodedInteranl(String[] array) {
		StringBuilder sb=new StringBuilder();
		int i=0;
		if (array != null) {
			for(String s: array) {
				if(i>0)sb.append(":");
				sb.append(s);
				i++;
			}
		}
		return sb.toString();
	}
	
	public boolean isMultiLogin(){
		return logins!=null && logins.length>1;
	}
	
	/**
	 * sets the login that should be used. The selection is checked.
	 * 
	 * @param login - the login to use
	 * @throws AAAException - in case the selected login is not one of the allowed logins
	 */
	public void setSelectedGroup(String group)throws SecurityException{
		if(isValidGroup(group))
			selectedGroup=group;
		else throw new SecurityException("Requested group <"+group+"> is not available.");
	}
	
	public boolean isGroupSelected() {
		return selectedGroup != null;
	}

	/**
	 * sets the login that should be used. The selection is checked.
	 * 
	 * @param login - the login to use
	 * @throws AAAException - in case the selected login is not one of the allowed logins
	 */
	public void setSelectedSupplementaryGroups(String[] groups)throws SecurityException{
		for (int i=0; i<groups.length; i++)
			if(!isValidGroup(groups[i]))
				throw new SecurityException("Requested group <"+groups[i]+"> is not available.");
		selectedSupplementaryGroups = Arrays.copyOf(groups, groups.length);
	}

	
	/**
	 * @param preferredGroup - the preferred group
	 * @return true if the valid groups contains the preferred one
	 */
	public boolean isValidGroup(String preferredGroup){
		if (preferredGroup == null) 
			return true;
		if (groups == null)
			return false;
		
		for(String s: groups){
			if(preferredGroup.equals(s))return true;
		}
		return false;
	}

	public String[] getGroups(){
		return groups == null ? null : groups.clone();
	}
	
	/**
	 * returns the default group, which is either the one selected using {@link #setSelectedGroup(String)},
	 * or the first entry in the list of groups
	*/
	public String getGroup(){
		if (selectedGroup != null)
			return selectedGroup;
		if (groups == null || groups.length == 0)
			return null;
		return groups[0];
	}
	
	public String[] getSelectedSupplementaryGroups() {
		return selectedSupplementaryGroups == null ? null :
			selectedSupplementaryGroups.clone();
	}

	public String getEncodedSelectedSupplementaryGroups() {
		return getEncodedInteranl(selectedSupplementaryGroups);
	}
		
	public String toString(){
		return "["+getEncoded()+(isMultiLogin()?", active = "+getUserName():"")+"]";
	}
	
	public void setAddDefaultGroups(boolean addDefaultGroups)
	{
		this.addDefaultGroups = addDefaultGroups;
	}

	public boolean isAddDefaultGroups()
	{
		return addDefaultGroups;
	}	
	
	
	//TODO Deprecated stuff to be deleted in 6.4	
	
	/**
	 * constructs a new Xlogin instance from the supplied ":"-separated
	 * list
	 * @see #getEncoded()
	 * @param encodedLogin - ":"-separated xlogins
	 * @deprecated Use version with array argument only
	 */
	@Deprecated
	public Xlogin(String encodedLogin){
		//quick&dirty parsing...
		logins=encodedLogin.split(":");
	}
	/**
	 * constructs a new Xlogin instance from the login and group
	 * specifications (which are ":"-separated lists)
	 * 
	 * @see #getEncoded()
	 * @param encodedLogin - the logins
	 * @param groups - the groups
	 * @deprecated Use version with array arguments
	 */
	@Deprecated
	public Xlogin(String encodedLogin, String encodedGroups){
		//quick&dirty parsing...
		logins=encodedLogin.split(":");
		groups=encodedGroups.split(":");
	}
	/**
	 * @deprecated Use getUserName() or isValid() to check whether your proposed xlogin is correct.
	*/
	@Deprecated
	public String getUserName(String preferred) throws SecurityException {
		if (preferred == null || !isValid(preferred))
			throw new SecurityException("Requested login <"+preferred+"> is not available.");
		return preferred;
	}
	
	/**
	 * returns the preferred group, i.e.
	 * <ul>
	 *  <li>if there are no groups available, returns <code>null</code></li>
	 *  <li>if no preference is specified, use the default one</li>
	 *  <li>check if the preferred one is OK</li>
	 *  <li>if not OK, throw an {@link AAAException}</li>
	 * </ul>
	 * @param preferredGroup - the preferred group
	 * @return group
	 * @deprecated - don't use it, not required.
	 */
	@Deprecated
	public String getGroup(String preferredGroup)throws SecurityException{
		if(groups==null)return null;
		
		String res=groups[0];
		if(preferredGroup==null)return res;
		
		for(String s: groups){
			if(preferredGroup.equals(s))return s;
		}
		
		throw new SecurityException("Requested group <"+preferredGroup+"> is not available.");
	}
}
