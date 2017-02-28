package nl.idfocus.nam.sms;

import nl.idfocus.nam.sms.code.RandomCode;

public class SmsMessage
{

	private final String	phoneNumber;
	private final String	altPhoneNumber;
	private String selectedPhoneNumber;
	private int delay;
	private RandomCode authToken;

	public SmsMessage(String primaryPhone, String secondaryPhone)
	{
		phoneNumber = primaryPhone;
		altPhoneNumber = secondaryPhone;
		selectedPhoneNumber = phoneNumber;
	}

	public SmsMessage setToken( RandomCode token )
	{
		authToken = token;
		return this;
	}

	public RandomCode getToken()
	{
		return authToken;
	}

	public boolean validateToken(String tokenString)
	{
		if ( authToken != null && tokenString != null && authToken.getCode().equalsIgnoreCase(tokenString))
			return true;
		return false;
	}

	public SmsMessage setDelay( int delay )
	{
		this.delay = delay;
		return this;
	}

	public SmsMessage setSelectedNumber(String number)
	{
		if( number != null && !number.isEmpty() &&
			( number.equals(phoneNumber) || number.equals(altPhoneNumber) ) )
				selectedPhoneNumber = number;
		return this;
	}

	public boolean hasValidNumber()
	{
		if ((phoneNumber == null || phoneNumber.isEmpty())
				&& (altPhoneNumber == null || altPhoneNumber.isEmpty()))
			return false;
		return true;
	}

	public String getPrimaryPhone()
	{
		return phoneNumber;
	}

	public boolean hasSecondaryPhone()
	{
		return altPhoneNumber != null && !altPhoneNumber.isEmpty();
	}

	public String getSecondaryPhone()
	{
		return altPhoneNumber;
	}

	public boolean hasDelay()
	{
		return delay > 0;
	}

	public int getDelay()
	{
		return delay;
	}

	public String getSelectedNumber()
	{
		return selectedPhoneNumber;
	}
}
