package eu.unicore.security;

/**
 * Represents assertion verification result.
 * @author K. Benedyczak
 */
public class ValidationResult
{

	private final boolean valid;

	private final String invalidReason;

	public ValidationResult(boolean valid, String invalidReason)
	{
		super();
		this.valid = valid;
		this.invalidReason = invalidReason;
	}

	public String getInvalidReason()
	{
		return invalidReason;
	}

	public boolean isValid()
	{
		return valid;
	}

	@Override
	public String toString()
	{
		return "Validation status: " + valid + ((!valid && invalidReason != null) ? 
				" " + invalidReason : "");
	}
}
