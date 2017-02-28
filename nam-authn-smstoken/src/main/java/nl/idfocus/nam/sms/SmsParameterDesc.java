package nl.idfocus.nam.sms;

public class SmsParameterDesc 
{

	private final String paramName;
	private final SmsParameterType type;

	public SmsParameterDesc( String name, SmsParameterType type ) 
	{
		this.paramName = name;
		this.type = type;
	}

	public String getName()
	{
		return paramName;
	}

	public SmsParameterType getType()
	{
		return type;
	}

	public enum SmsParameterType
	{
		STRING,
		INTEGER,
		BOOLEAN,
		ATTRIBUTE;
	}

}
