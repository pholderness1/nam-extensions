package nl.idfocus.nam.password;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

public enum PwdPolicy
{

//	PWD_EXPIRATION  ( "passwordExpirationInterval"   , "PWD_EXPIRATION"  , "", 1 ),
//	PWD_GRACECOUNT  ( "loginGraceLimit"              , "PWD_GRACECOUNT"  , "", 2 ),
//	PWD_LIFETIME_MIN( "nspmMinPasswordLifetime"      , "PWD_LIFETIME_MIN", "", 3 ),
	CHANGE_ALLOWED  ( "passwordAllowChange"          , "CHANGE_ALLOWED", "CHANGE_DISALLOWED", 4 ),
	CHANGE_MESSAGE  ( "nspmChangePasswordMessage"    , "CHANGE_MESSAGE", "", 5 ),
	CASE_SENSITIVE  ( "nspmCaseSensitive"            , "CASE_SENSITIVE", "CASE_INSENSITIVE", 6 ),
//	COMPLEXITY_RULES( "nspmComplexityRules"          , "COMPLEXITY_RULES", "", 7 ),
	LENGTH_MIN      ( "passwordMinimumLength"        , "LENGTH_MIN"   , "", 10 ),
	LENGTH_MAX      ( "nspmMaximumLength"            , "LENGTH_MAX"   , "", 11 ),
	CHAR_REPEAT     ( "nspmMaxRepeatedCharacters"    , "CHAR_REPEAT"     , "", 12 ),
	CHAR_CONSECUTIVE( "nspmMaxConsecutiveCharacters" , "CHAR_CONSECUTIVE", "", 13 ),
	ALLOW_EXTENDED  ( "nspmExtendedCharactersAllowed", "ALLOW_EXTENDED", "DISALLOW_EXTENDED", 15 ),
	ALLOW_SPECIAL   ( "nspmSpecialCharactersAllowed" , "ALLOW_SPECIAL" , "DISALLOW_SPECIAL" , 16 ),
	ALLOW_NUMERIC   ( "nspmNumericCharactersAllowed" , "ALLOW_NUMERIC" , "DISALLOW_NUMERIC" , 17 ),
	MIN_EXTENDED    ( "nspmMinExtendedCharacters"    , "MIN_EXTENDED" , "", 21 ),
	MIN_SPECIAL     ( "nspmMinSpecialCharacters"     , "MIN_SPECIAL"  , "", 22 ),
	MIN_NUMERIC     ( "nspmMinNumericCharacters"     , "MIN_NUMERIC"  , "", 23 ),
	MIN_LOWERCASE   ( "nspmMinLowerCaseCharacters"   , "MIN_LOWERCASE", "", 24 ),
	MIN_UPPERCASE   ( "nspmMinUpperCaseCharacters"   , "MIN_UPPERCASE", "", 25 ),
	MAX_EXTENDED    ( "nspmMaxExtendedCharacters"    , "MAX_EXTENDED" , "", 31 ),
	MAX_SPECIAL     ( "nspmMaxSpecialCharacters"     , "MAX_SPECIAL"  , "", 32 ),
	MAX_NUMERIC     ( "nspmMaxNumericCharacters"     , "MAX_NUMERIC"  , "", 33 ),
	MAX_LOWERCASE   ( "nspmMaxLowerCaseCharacters"   , "MAX_LOWERCASE", "", 34 ),
	MAX_UPPERCASE   ( "nspmMaxUpperCaseCharacters"   , "MAX_UPPERCASE", "", 35 ),
	FIRST_EXTENDED  ( "nspmExtendedAsFirstCharacter" , "", "FIRST_EXTENDED" , 41 ),
	FIRST_SPECIAL   ( "nspmSpecialAsFirstCharacter"  , "", "FIRST_SPECIAL"  , 42 ),
	FIRST_NUMERIC   ( "nspmNumericAsFirstCharacter"  , "", "FIRST_NUMERIC"  , 43 ),
	FIRST_LOWERCASE ( "nspmLowerAsFirstCharacter"    , "", "FIRST_LOWERCASE", 44 ),
	FIRST_UPPERCASE ( "nspmUpperAsFirstCharacter"    , "", "FIRST_UPPERCASE", 45 ),
	LAST_EXTENDED   ( "nspmExtendedAsLastCharacter"  , "", "LAST_EXTENDED" , 51 ),
	LAST_SPECIAL    ( "nspmSpecialAsLastCharacter"   , "", "LAST_SPECIAL"  , 52 ),
	LAST_NUMERIC    ( "nspmNumericAsLastCharacter"   , "", "LAST_NUMERIC"  , 53 ),
	LAST_LOWERCASE  ( "nspmLowerAsLastCharacter"     , "", "LAST_LOWERCASE", 54 ),
	LAST_UPPERCASE  ( "nspmUpperAsLastCharacter"     , "", "LAST_UPPERCASE", 55 ),
	UNIQUE_REQUIRED ( "passwordUniqueRequired"       , "UNIQUE_REQUIRED" , "", 61 ),
//	UNIQUE_COUNT    ( "pwdInHistory"                 , "UNIQUE_COUNT"    , "", 62 ),
	EXCLUDE_LIST    ( "nspmExcludeList"              , "EXCLUDE_LIST"    , "", 63 ),
//	EXCLUDE_ATTRS   ( "nspmDisallowedAttributeValues", "EXCLUDE_ATTRS"   , "", 64 ),
	;

	private final static Logger logger = Logger.getLogger( PwdPolicy.class.getName() );
	private final static Level loglevel = Level.INFO;
	private final String attributeName;
	private final String keyOn;
	private final String keyOff;
	private final int order;
	private String attrValue = null;

	private PwdPolicy( String attribute, String keyOn, String keyOff, int order )
	{
		this.attributeName = attribute;
		this.keyOn = keyOn;
		this.keyOff = keyOff;
		this.order = order;
	}

	/**
	 * 
	 * @param value
	 */
	public void setValue( String value )
	{
		this.attrValue = value;
	}

	/**
	 * 
	 * @return
	 */
	public String getValue()
	{
		return this.attrValue;
	}

	/**
	 * 
	 * @return
	 */
	public String getAttribute()
	{
		return this.attributeName;
	}

	/**
	 * 
	 * @return
	 */
	public int getOrder()
	{
		return this.order;
	}

    /* ##############################  Messages Methods  ############################# */

	/**
	 * 
	 * @param locale
	 * @return
	 */
	public String getDisabledMessage( Locale locale )
	{
		return getMessage(locale, true);
	}

	/**
	 * 
	 * @return
	 */
	public String getMessage()
	{
		return getMessage( null );
	}

	/**
	 * 
	 * @param locale
	 * @return
	 */
	public String getMessage( Locale locale )
	{
		return getMessage(locale, false);
	}

	/**
	 * 
	 * @param locale
	 * @param disabled
	 * @return
	 */
	public String getMessage( Locale locale, boolean disabled )
	{
		String key = disabled ? this.keyOff : this.keyOn;
        final ResourceBundle bundle = getMessageBundle( locale );
        return bundle.getString( key );
	}

	/**
	 * 
	 * @param value
	 * @param locale
	 * @return
	 */
	public String getMessage( String value, Locale locale ) 
	{
		String key = this.keyOn;
		boolean multi = false;
		try {
			int count = Integer.parseInt(value);
			if ( count > 1 )
				multi = true;
		} catch (NumberFormatException e) {}
        final ResourceBundle bundle = getMessageBundle( locale );
        // TODO this should be dependent on the locale
        return MessageFormat.format( bundle.getString( key ), value, multi ? "s" : "", multi ? "e" : "", multi ? "" : "a" );
	}

	/**
	 * 
	 * @param locale
	 * @return
	 */
    private ResourceBundle getMessageBundle( final Locale locale )
    {
        final ResourceBundle messageBundle;
        if (locale == null)
        {
            messageBundle = ResourceBundle.getBundle( PwdPolicy.class.getName() );
        } else {
            messageBundle = ResourceBundle.getBundle( PwdPolicy.class.getName(), locale );
        }

        return messageBundle;
    }

    /* ##############################  Static Methods  ############################# */

    /**
	 * Get a list of all known LDAP attribute names to retrieve from the password policy
	 * @return
	 */
	public static String[] getAttributeNames()
	{
		List<String> attributeNames = new ArrayList<String>();
		for ( PwdPolicy attr : PwdPolicy.values() )
		{
			attributeNames.add( attr.getAttribute() );
		}
		String[] result = attributeNames.toArray( new String[attributeNames.size()] );
		logger.log( loglevel, "Returning attribute names: "+Arrays.toString(result) );
		return result;
	}

	public static PwdPolicy resolveValue( String attrName )
	{
//		logger.log(loglevel, "Resolving value for "+attrName );
		for ( PwdPolicy attr : PwdPolicy.values() )
		{
			if ( attr.getAttribute().equalsIgnoreCase( attrName ) )
			{
//				logger.log( loglevel, "Returning "+attr.name() );
				return attr;
			}
		}
//		logger.log(loglevel, "Returning null!");
		return null;
	}

	/** 
	 * Assemble the list of message texts from the derived policy attributes
	 * @param attributes
	 * @return
	 */
	public static String[] getMessageList( List<PwdPolicy> attributes, Locale locale )
	{
		logger.log(loglevel, "Resolving message list for "+attributes.size()+" attributes");
		List<String> messages = new ArrayList<String>();
		boolean allowChange = false;
		boolean allowExt = false;
		boolean allowSpec = false;
		boolean allowNum = false;
		// Get the boolean modifiers first
		for ( PwdPolicy attribute : attributes )
		{
			if      ( attribute == PwdPolicy.CHANGE_ALLOWED && Boolean.parseBoolean( attribute.getValue() ) )
			{
//				logger.log( loglevel, "Setting allowChange to true" );
				allowChange = true;
			}
			else if ( attribute == PwdPolicy.ALLOW_EXTENDED && Boolean.parseBoolean( attribute.getValue() ) )
			{
//				logger.log( loglevel, "Setting allowExt to true" );
				allowExt = true;
			}
			else if ( attribute == PwdPolicy.ALLOW_SPECIAL && Boolean.parseBoolean( attribute.getValue() ) )
			{
//				logger.log( loglevel, "Setting allowSpec to true" );
				allowSpec = true;
			}
			else if ( attribute == PwdPolicy.ALLOW_NUMERIC && Boolean.parseBoolean( attribute.getValue() ) )
			{
//				logger.log( loglevel, "Setting allowNum to true" );
				allowNum = true;
			}
		}
		// Next, get the messages themselves
		if ( allowChange )
		{
			for ( PwdPolicy attribute : attributes )
			{
//				logger.log( loglevel, "Handling policy attribute: "+attribute.name()+" with value "+attribute.getValue() );
				if      ( attribute == PwdPolicy.CHANGE_MESSAGE )
				{
					messages.add( attribute.getMessage( attribute.getValue(), locale ) );
				}
				else if ( attribute == PwdPolicy.MIN_EXTENDED || attribute == PwdPolicy.MAX_EXTENDED ) 
				{
					if ( allowExt )
						messages.add( attribute.getMessage( attribute.getValue(), locale ) );
				}
				else if ( attribute == PwdPolicy.FIRST_EXTENDED || attribute == PwdPolicy.LAST_EXTENDED )
				{
					if ( allowExt && ! Boolean.parseBoolean(attribute.getValue()) ) 
						messages.add( attribute.getDisabledMessage( locale ) );
				}
				else if ( attribute == PwdPolicy.MIN_SPECIAL || attribute == PwdPolicy.MAX_SPECIAL ) 
				{
					if ( allowSpec )
						messages.add( attribute.getMessage( attribute.getValue(), locale ) );
				}
				else if ( attribute == PwdPolicy.FIRST_SPECIAL || attribute == PwdPolicy.LAST_SPECIAL )
				{
					if ( allowSpec && ! Boolean.parseBoolean(attribute.getValue()) )
						messages.add( attribute.getDisabledMessage( locale ) );
				}
				else if ( attribute == PwdPolicy.MIN_NUMERIC || attribute == PwdPolicy.MAX_NUMERIC ) 
				{
					if ( allowNum )
						messages.add( attribute.getMessage( attribute.getValue(), locale ) );
				}
				else if ( attribute == PwdPolicy.MIN_LOWERCASE || 
						  attribute == PwdPolicy.MAX_LOWERCASE ||
						  attribute == PwdPolicy.MIN_UPPERCASE || 
						  attribute == PwdPolicy.MAX_UPPERCASE ) 
				{
					if ( allowNum )
						messages.add( attribute.getMessage( attribute.getValue(), locale ) );
				}
				else if ( attribute == PwdPolicy.FIRST_NUMERIC || attribute == PwdPolicy.LAST_NUMERIC )
				{
					if ( allowNum && ! Boolean.parseBoolean(attribute.getValue()) )	
						messages.add( attribute.getDisabledMessage( locale ) );
				}
				else if ( attribute == PwdPolicy.CASE_SENSITIVE )
				{
					if ( Boolean.parseBoolean( attribute.getValue() ) )
						messages.add( attribute.getMessage( locale ) );
				}
				else if ( attribute == PwdPolicy.ALLOW_EXTENDED )
				{
					if ( ! allowExt )
					{
//						logger.log( loglevel, "Adding message: "+attribute.getDisabledMessage(locale) );
						messages.add( attribute.getDisabledMessage(locale) );
					}
				}
				else if ( attribute == PwdPolicy.ALLOW_SPECIAL )
				{
					if ( ! allowSpec )
					{
//						logger.log( loglevel, "Adding message: "+attribute.getDisabledMessage(locale) );
						messages.add( attribute.getDisabledMessage(locale) );
					}
				}
				else if ( attribute == PwdPolicy.ALLOW_NUMERIC )
				{
					if ( ! allowNum )
					{
//						logger.log( loglevel, "Adding message: "+attribute.getDisabledMessage(locale) );
						messages.add( attribute.getDisabledMessage(locale) );
					}
				}
				else if ( attribute == PwdPolicy.LENGTH_MIN || 
						  attribute == PwdPolicy.LENGTH_MAX ||
						  attribute == PwdPolicy.CHAR_CONSECUTIVE ||
						  attribute == PwdPolicy.CHAR_REPEAT )
				{
//					logger.log( loglevel, "Adding value for "+attribute.name()+": "+attribute.getValue() );
					messages.add( attribute.getMessage( attribute.getValue(), locale) );
				}
				else if ( attribute == PwdPolicy.UNIQUE_REQUIRED )
				{
					if ( Boolean.parseBoolean( attribute.getValue()) )
						messages.add( attribute.getMessage(locale) );
				}
				else if ( attribute == PwdPolicy.EXCLUDE_LIST )
				{
					messages.add( attribute.getMessage( attribute.getValue(), locale) );
				}
			}
		} else {
			// Add the disallowed change message
			messages.add( PwdPolicy.CHANGE_ALLOWED.getDisabledMessage( locale ) );
		}
		logger.log( loglevel, "Returning "+messages.size()+" lines of policy text" );
		return messages.toArray( new String[messages.size()] );
	}

}
