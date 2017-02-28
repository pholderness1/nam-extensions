package nl.idfocus.nam.sms;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import nl.idfocus.nam.util.Base64;

public class SmsConfig
{
	public static final String	PRINCIPAL_DN	= "principalDn";

	private Map<String, Object>	params;

	public SmsConfig()
	{
		this.params = new HashMap<>();
	}

	public SmsConfig(Properties props, SmsParameterDesc[] paramsDesc)
	{
		this.params = new HashMap<>();
		for (SmsParameterDesc paramDesc : paramsDesc)
		{
			if (!paramDesc.getType().equals(SmsParameterDesc.SmsParameterType.ATTRIBUTE)
					&& props.containsKey(paramDesc.getName()))
				this.params.put(paramDesc.getName(), props.getProperty(paramDesc.getName()));
		}
	}

	public void addParam(String key, Object value)
	{
		this.params.put(key, value);
	}

	public boolean hasParam(String key)
	{
		return this.params.containsKey(key);
	}

	public String getStringValue(String key)
	{
		if (this.params.containsKey(key))
		{
			return (String) this.params.get(key);
		}
		return null;
	}

	public int getIntValue(String key)
	{
		if (this.params.containsKey(key))
		{
			return Integer.parseInt((String) this.params.get(key));
		}
		return -1;
	}

	public String getPasswordValue(String key)
	{
		// TODO something less obvious for the encoding but still workable
		// (secretstore?)
		if (this.params.containsKey(key))
		{
			try
			{
				return new String(Base64.decode((String) this.params.get(key)), "UTF-8");
			}
			catch (UnsupportedEncodingException e)
			{
				throw new IllegalStateException(e);
			}
		}
		return null;
	}
}
