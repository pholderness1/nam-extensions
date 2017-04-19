package nl.idfocus.nam.totp.store;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

import com.novell.nidp.NIDPException;
import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.common.authority.UserAuthority;

import nl.idfocus.nam.totp.TOTPException;

public class PwmStore implements ISecretStore
{
	public static final String	PROP_STORAGE_ATTRIBUTE_NAME	= "SecretKeyAttribute";
	public static final String	PROP_STORAGE_FORMAT_NAME	= "SecretKeyFormat";

	public static final String	FORMAT_JSON					= "JSON";
	/**
	 * Use the format from google's TOTP PAM module
	 * @see https://github.com/google/google-authenticator-libpam/blob/master/FILEFORMAT
	 */
	public static final String	FORMAT_PAM					= "PAM";

	private static final String	LINE_END					= "\\r\\n";
	private static final String	PAM_OPTION_START			= "\" ";
	private static final String	PAM_OPTION_TOTP				= "TOTP_AUTH";

	private String				storageFormat;
	private String				storageAttribute;

	@Override
	public void init(Properties props) throws TOTPException
	{
		storageAttribute = props.getProperty(PROP_STORAGE_ATTRIBUTE_NAME, "description");
		storageFormat = props.getProperty(PROP_STORAGE_FORMAT_NAME, FORMAT_PAM);
	}

	@Override
	public void writeSecretToStore(NIDPPrincipal princ, String secretValue) throws TOTPException
	{
		List<Integer> scratchCodes = readScratchCodesFromStore(princ);
		String value;
		if (FORMAT_PAM.equals(storageFormat))
			value = generatePAMStorageValue(secretValue, scratchCodes);
		else
			value = generateJSONStorageValue(secretValue, scratchCodes);
		writeValueToStore(princ, storageAttribute, value);
	}

	@Override
	public String readSecretFromStore(NIDPPrincipal princ) throws TOTPException
	{
		Attribute attr = readAttributeFromPrincipal(princ, storageAttribute);
		try
		{
			if (FORMAT_PAM.equals(storageFormat))
				return retrieveKeyFromPAMValue((String) attr.get());
			else
				return retrieveKeyFromJSONValue((String) attr.get());
		}
		catch (NamingException | NullPointerException e)
		{
			throw new TOTPException("failed to read secret key: " + e.getMessage(), e);
		}
	}

	@Override
	public void writeScratchCodesToStore(NIDPPrincipal princ, Integer... secretValue)
			throws TOTPException
	{
		List<Integer> scratchCodes = Arrays.asList(secretValue);
		String key = readSecretFromStore(princ);
		String value;
		if (FORMAT_PAM.equals(storageFormat))
			value = generatePAMStorageValue(key, scratchCodes);
		else
			value = generateJSONStorageValue(key, scratchCodes);
		writeValueToStore(princ, storageAttribute, value);
	}

	@Override
	public List<Integer> readScratchCodesFromStore(NIDPPrincipal princ) throws TOTPException
	{
		Attribute attr = readAttributeFromPrincipal(princ, storageAttribute);
		try
		{
			if (FORMAT_PAM.equals(storageFormat))
				return retrieveScratchcodesFromPAMValue((String) attr.get());
			else
				return retrieveScratchcodesFromJSONValue((String) attr.get());
		}
		catch (NamingException | NullPointerException e)
		{
			throw new TOTPException("failed to read scratch codes: " + e.getMessage(), e);
		}
	}

	private Attribute readAttributeFromPrincipal(NIDPPrincipal princ, String attrName) throws TOTPException
	{
		try
		{
			UserAuthority ua = princ.getAuthority();
			Attributes attrs = ua.getAttributes(princ, new String[] { attrName });
			return attrs.get(attrName);
		}
		catch (NullPointerException e)
		{
			throw new TOTPException("Could not read principal attributes", e);
		}
	}

	private void writeValueToStore(NIDPPrincipal princ, String attribute, String value) throws TOTPException
	{
		UserAuthority ua = princ.getAuthority();
		try
		{
			ua.modifyAttributes(princ, new String[] { attribute }, new String[] { value });
		}
		catch (NIDPException e)
		{
			throw new TOTPException(
					"failed to save secret value in " + attribute + ": " + e.getMessage(), e);
		}
	}

	private String generatePAMStorageValue(String key, List<Integer> scratchCodes)
	{
		StringBuilder result = new StringBuilder();
		result.append(key).append(LINE_END).append(PAM_OPTION_START).append(PAM_OPTION_TOTP)
				.append(LINE_END);
		for (Integer code : scratchCodes)
		{
			result.append(code.toString()).append(LINE_END);
		}
		return result.toString();
	}

	private String retrieveKeyFromPAMValue(String pamValue)
	{
		String[] values = new String[] { "" };
		if (pamValue != null && !pamValue.isEmpty())
			values = pamValue.split(LINE_END);
		return values[0];
	}

	private List<Integer> retrieveScratchcodesFromPAMValue(String pamValue)
	{
		List<Integer> result = new ArrayList<>();
		String[] values = new String[] {};
		if (pamValue != null && !pamValue.isEmpty())
			values = pamValue.split(LINE_END);
		boolean seenKey = false;
		for (String value : values)
		{
			if (value.startsWith(PAM_OPTION_START))
				continue;
			if (seenKey && value.matches("\\d+"))
				result.add(Integer.parseInt(value));
			if (!seenKey)
				seenKey = true;
		}
		return result;
	}

	private String generateJSONStorageValue(String key, List<Integer> scratchCodes)
	{
		// TODO
		StringBuilder result = new StringBuilder();
		return result.toString();
	}

	private List<Integer> retrieveScratchcodesFromJSONValue(String jsonValue)
	{
		// TODO 
		List<Integer> result = new ArrayList<>();
		return result;
	}

	private String retrieveKeyFromJSONValue(String jsonValue)
	{
		// TODO
		StringBuilder result = new StringBuilder();
		return result.toString();
	}

}
