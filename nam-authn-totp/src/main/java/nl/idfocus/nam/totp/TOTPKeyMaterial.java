package nl.idfocus.nam.totp;

import java.io.Serializable;
import java.util.List;

public class TOTPKeyMaterial implements Serializable
{
	private static final long serialVersionUID = 4563989505758743121L;

	private final String secretKey;
	private final List<Integer> scratchCodes;
	private final int primerCode;

	public TOTPKeyMaterial(String secretKey, List<Integer> scratchCodes, int primerCode)
	{
		this.secretKey = secretKey;
		this.scratchCodes = scratchCodes;
		this.primerCode = primerCode;
	}

	public String getKey()
	{
		return secretKey;
	}

	public List<Integer> getScratchCodes()
	{
		return scratchCodes;
	}

	public int getPrimerCode()
	{
		return primerCode;
	}
}
