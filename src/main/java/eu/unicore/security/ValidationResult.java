package eu.unicore.security;

/**
 * Represents assertion verification result.
 * @author K. Benedyczak
 */
public class ValidationResult
{
	private boolean valid;
	private String invalidResaon;
	
	public ValidationResult(boolean valid, String invalidResaon)
	{
		super();
		this.valid = valid;
		this.invalidResaon = invalidResaon;
	}
	
	public String getInvalidResaon()
	{
		return invalidResaon;
	}
	
	public void setInvalidResaon(String invalidResaon)
	{
		this.invalidResaon = invalidResaon;
	}
	
	public boolean isValid()
	{
		return valid;
	}
	
	public void setValid(boolean valid)
	{
		this.valid = valid;
	}
	
	public String toString()
	{
		return "Validation status: " + valid + ((!valid && invalidResaon != null) ? 
				" " + invalidResaon : "");
	}
}
