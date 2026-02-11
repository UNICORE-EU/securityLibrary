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
	 * @throws SecurityException - in case the selected login is not one of the allowed logins
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
	 * sets the group that should be used. The selection is checked.
	 * 
	 * @param group - the group to use
	 * @throws SecurityException - in case the selected login is not one of the allowed logins
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
	 * sets the supplementary groups that should be used. The selection is checked.
	 * 
	 * @param groups - the groups to use
	 * @throws SecurityException - in case the selected login is not one of the allowed logins
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
		
	public String toString() {
		StringBuilder cInfo = new StringBuilder(256);
		
		cInfo.append("uid: [");
		cInfo.append(getEncoded());
		if (isMultiLogin()) 
		{
			cInfo.append(", active=");
			cInfo.append(getUserName());
		}
		cInfo.append("], gids: [");

		if (groups != null && groups.length > 0) {
			cInfo.append(getEncodedGroups());
			if (groups.length > 1) {
				cInfo.append(", active=");
				cInfo.append(getGroup());
			}
			if (selectedSupplementaryGroups != null &&
					selectedSupplementaryGroups.length > 0) {
				cInfo.append(", selectedSupplementaryGids=");
				cInfo.append(getEncodedSelectedSupplementaryGroups());
			}
			cInfo.append(", ");
		}
		cInfo.append("addingOSgroups: ");
		cInfo.append(isAddDefaultGroups());
		cInfo.append("]");
		
		return cInfo.toString();
	}
	
	public void setAddDefaultGroups(boolean addDefaultGroups)
	{
		this.addDefaultGroups = addDefaultGroups;
	}

	public boolean isAddDefaultGroups()
	{
		return addDefaultGroups;
	}	
}
