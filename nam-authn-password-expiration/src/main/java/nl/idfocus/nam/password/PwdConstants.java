package nl.idfocus.nam.password;

import java.util.Locale;
import java.util.ResourceBundle;

public enum PwdConstants 
{

	PASSWORD_ERROR_TOO_SHORT         ( "", "PASSWORD_TOO_SHORT",            216 ),
	PASSWORD_ERROR_TOO_LONG          ( "", "PASSWORD_TOO_LONG",           16000 ),
	PASSWORD_ERROR_UPPER_MIN         ( "", "PASSWORD_UPPER_MIN",          16001 ),
	PASSWORD_ERROR_LOWER_MIN         ( "", "PASSWORD_LOWER_MIN",          16003 ),
	PASSWORD_ERROR_NUMERIC_MIN       ( "", "PASSWORD_NUMERIC_MIN",        16008 ),
	PASSWORD_ERROR_SPECIAL_DISALLOWED( "", "PASSWORD_SPECIAL_DISALLOWED", 16010 ),
	PASSWORD_ERROR_SPECIAL_MIN       ( "", "PASSWORD_SPECIAL_MIN",        16013 ),
	PASSWORD_ERROR_IN_HISTORY        ( "", "PASSWORD_IN_HISTORY",           215 ),
	PASSWORD_ERROR_HISTORY_FULL      ( "", "PASSWORD_HISTORY_FULL",        1696 ),
	PASSWORD_ERROR_UNKNOWN           ( "", "PASSWORD_UNKNOWN_ERROR",          0 )
	;

	private String logMessage;
	private String messageKey;
	private int errorCode;

	PwdConstants( final String log, final String key, final int code )
	{
		this.logMessage = log;
		this.messageKey = key;
		this.errorCode = code;
	}

	public String getLogMessage()
	{
		return this.logMessage;
	}

	public String getMessageKey()
	{
		return messageKey;
	}

	public int getCode()
	{
		return errorCode;
	}

	public String getMessage()
	{
        return this.getLocalizedMessage( null );
	}

	public String getLocalizedMessage( final Locale locale )
	{
        final ResourceBundle bundle = getMessageBundle( locale );
        return bundle.getString( this.messageKey );
	}

    private ResourceBundle getMessageBundle( final Locale locale )
    {
        final ResourceBundle messageBundle;
        if (locale == null)
        {
            messageBundle = ResourceBundle.getBundle( PwdConstants.class.getName() );
        } else {
            messageBundle = ResourceBundle.getBundle( PwdConstants.class.getName(), locale );
        }

        return messageBundle;
    }

}
