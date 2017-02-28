package nl.idfocus.nam.authentication;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.SortedMap;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.servlet.http.Cookie;

import com.novell.nidp.NIDPConstants;
import com.novell.nidp.NIDPException;
import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.NIDPSubject;
import com.novell.nidp.authentication.AuthnConstants;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.authentication.local.PageToShow;
import com.novell.nidp.common.authority.UserAuthority;

import nl.idfocus.nam.sms.MessageBird;
import nl.idfocus.nam.sms.SmsConfig;
import nl.idfocus.nam.sms.SmsConstants;
import nl.idfocus.nam.sms.SmsMessage;
import nl.idfocus.nam.sms.SmsParameterDesc;
import nl.idfocus.nam.sms.SmsParameterDesc.SmsParameterType;
import nl.idfocus.nam.sms.SmsProvider;
import nl.idfocus.nam.sms.code.RandomCode;
import nl.idfocus.nam.totp.Authenticator;
import nl.idfocus.nam.totp.TOTPConstants;
import nl.idfocus.nam.totp.TOTPException;
import nl.idfocus.nam.util.LogFormatter;
import nl.idfocus.nam.util.Sha256;

/**
 * Custom Authentication class for NetIQ Access Manager<br/>
 * <p>
 * The SmsToken class allows for extra authentication using a generated token in an SMS text message. <br/>
 * </p><p>
 * During authentication, the mobile number of the user logging in is retrieved, a unique code is generated<br/>
 * and sent to the mobile. The user is prompted for the token which is then checked server-side. <br/>
 * An additional functionality is the ability for the user to skip SMS authentication for the next X days<br/>
 * by means of a browser cookie. <br/>
 * </p>
 * @author IDFocus B.V. (mvreijn@idfocus.nl)
 * @version Tested on NetIQ Access Manager 4.0.x and 4.1.x
 *
 */
public class SmsToken extends LocalAuthenticationClass 
{
	// Logging
	private static final Logger logger   = LogFormatter.getConsoleLogger( SmsToken.class.getName() );

	// Configuration properties we know of
	/**
	 * By setting this property name on the class or method, the debug mode may be enabled. 
	 * This overrides the default specified in {@link #DEF_DEBUG}
	 */
	private static final String PROP_DEBUG   = "DEBUG";
	/**
	 * By setting this property name on the class or method, the name of the token <br/>
	 * input field may be altered from the default specified in {@link #DEF_INPUT_TOKEN}
	 */
	private static final String PROP_INPUT_TOKEN    = "inputToken";
	/**
	 * By setting this property name on the class or method, the name of the 'postpone' <br/>
	 * input field may be altered from the default specified in {@link #DEF_INPUT_POSTPONE}
	 */
	private static final String PROP_INPUT_POSTPONE = "inputPostpone";
	/**
	 * By setting this property name on the class or method, the name of the 'number' <br/>
	 * input field may be altered from the default specified in {@link #DEF_INPUT_NUMBER}
	 */
	private static final String PROP_INPUT_NUMBER   = "inputNumber";
	/**
	 * By setting this property name on the class or method, the name of the 'retry' <br/>
	 * input field may be altered from the default specified in {@link #DEF_INPUT_RETRY}
	 */
	private static final String PROP_INPUT_RETRY    = "inputRetry";
	/**
	 * By setting this property name on the class or method, the name of the <br/>
	 * sms authentication web page may be altered from the default specified in {@link #DEF_INPUT_JSP}
	 */
	private static final String PROP_INPUT_JSP      = "JSP";
	/**
	 * By setting this property name on the class or method, the length of the <br/>
	 * sms authentication token may be altered from the default specified in {@link #DEF_TOKEN_LENGTH}
	 */
	private static final String PROP_TOKEN_LENGTH   = "tokenLength";
	/**
	 * By setting this property name on the class or method, the contents of the <br/>
	 * sms authentication token may be altered from the default specified in {@link #DEF_TOKEN_CHARSET}
	 */
	private static final String PROP_TOKEN_CHARSET  = "tokenCharacters";
	/**
	 * By setting this property name on the class or method, the class of the <br/>
	 * sms authentication provider may be altered from the default specified in {@link #DEF_SMS_PROVIDER}
	 */
	private static final String PROP_SMS_PROVIDER   = "smsProvider";
	/**
	 * By setting this property name on the class or method, the LDAP attribute containing <br/>
	 * users' mobile number may be altered from the default specified in {@link #DEF_SMS_ATTRIBUTE}
	 */
	private static final String PROP_SMS_ATTRIBUTE  = "mobileAttribute";
	/**
	 * By setting this property name on the class or method, the LDAP attribute containing <br/>
	 * users' alternative mobile number may be altered from the default specified in {@link #DEF_SMS_ALTATTR}
	 */
	private static final String PROP_SMS_ALTATTR    = "mobileAltAttribute";
	/**
	 * By setting this property name on the class or method, the name of the cookie containing <br/>
	 * the authentication expiration may be altered from the default specified in {@link #DEF_EXP_COOKIE}
	 */
	private static final String PROP_EXP_COOKIE     = "expirationCookie";
	/**
	 * By setting this property name on the class or method, the default lifetime in days <br/>
	 * of the authentication cookie may be altered from the default specified in {@link #DEF_EXP_TIME}
	 */
	private static final String PROP_EXP_TIME       = "expirationTime";
	/**
	 * By setting this property name on the class or method, the name of the attribute containing <br/>
	 * the authentication expiration may be altered from the default specified in {@link #DEF_EXP_ATTRIBUTE}
	 */
	private static final String PROP_EXP_ATTRIBUTE  = "expirationAttribute";	
	/**
	 * By setting this property name on the class or method, the SMS send timeout <br/>
	 * may be altered from the default specified in {@link #DEF_EXP_ATTRIBUTE}
	 */
	private static final String PROP_SMS_TIMEOUT    = "smsSendTimeout";	
	// Defaults
	private static final String DEF_INPUT_TOKEN    = "Ecom_Token";
	private static final String DEF_INPUT_POSTPONE = "Ecom_Postpone";
	private static final String DEF_INPUT_NUMBER   = "Ecom_Number";
	private static final String DEF_INPUT_RETRY    = "Ecom_Retry";
	private static final String DEF_INPUT_JSP      = "smstoken";
	private static final String DEF_TOKEN_LENGTH   = "8";
	private static final String DEF_TOKEN_CHARSET  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	private static final String DEF_SMS_PROVIDER   = MessageBird.class.getName();
	private static final String DEF_SMS_ATTRIBUTE  = "mobile";
	private static final String DEF_SMS_ALTATTR    = "";
	private static final String DEF_SMS_TIMEOUT    = "10000";
	private static final String DEF_EXP_COOKIE     = "idfsmsauth";
	private static final String DEF_EXP_TIME       = "0";
	private static final String DEF_EXP_ATTRIBUTE  = "description";
	// Actual values
	private final String valInputToken;
	private final String valInputPostpone;
	private final String valInputNUMBER;
	private final String valInputRETRY;
	private final String valInputJSP;
	private final int    valInputLENGTH;
	private final String valInputCHARSET;
	private final String valSmsPROVIDER;
	private final String valSmsATTRIBUTE;
	private final String valSmsALTATTR;
	private final int    valSmsTIMEOUT;
	private final String valExpCOOKIE;
	private final String valExpATTRIBUTE;
	private final int    valExpTIME;
	// Variables
	private NIDPPrincipal localPrincipal;
	private final String sessionUser;
	private SmsConfig conf;
	private SmsProvider provider;
	private SortedMap<String,String> attrNames;
	private final boolean debugMode;

	private static final String LAST_CHANGED_REVISION = "$LastChangedRevision: 85 $";
	private final String revision;

	/**
	 * The constructor is always called by the NIDP and all params are passed into it. 
	 * @param props configuration properties from the class and method definition
	 * @param stores the user stores
	 * @throws NIDPException
	 */
	public SmsToken(Properties props, ArrayList<UserAuthority> stores) throws NIDPException 
	{
		super( props, stores );
		this.revision = LAST_CHANGED_REVISION.substring( LAST_CHANGED_REVISION.indexOf(':')+1, LAST_CHANGED_REVISION.lastIndexOf('$') ).trim();
		logger.log( Level.INFO, "SMS Token Authentication Class rev "+revision+" (c) IDFocus B.V. <info@idfocus.nl>" );
		logger.log( Level.FINE, "Initializing SmsToken" );
		// Determine debug setting
		debugMode = Boolean.parseBoolean( props.getProperty(PROP_DEBUG, "false" ) );
		if ( debugMode )
		{
			LogFormatter.setLoggerDebugMode(logger);
			logger.log( Level.FINER, "$Id: SmsToken.java 85 2017-02-08 16:10:44Z mvreijn $" );
			// Read setup properties DEBUG
			Iterator<?> itr = props.keySet().iterator();
			while ( itr.hasNext() )
			{
				String key = (String) itr.next();
				logger.log( Level.FINEST, "[DBG] property "+key+": "+ props.getProperty(key) );
			}
		}
		// Read known settings
		valInputToken    = props.getProperty( PROP_INPUT_TOKEN   , DEF_INPUT_TOKEN );
		valInputPostpone = props.getProperty( PROP_INPUT_POSTPONE, DEF_INPUT_POSTPONE );
		valInputNUMBER   = props.getProperty( PROP_INPUT_NUMBER  , DEF_INPUT_NUMBER );
		valInputRETRY    = props.getProperty( PROP_INPUT_RETRY   , DEF_INPUT_RETRY );
		valInputJSP      = props.getProperty( PROP_INPUT_JSP     , DEF_INPUT_JSP );
		valInputCHARSET  = props.getProperty( PROP_TOKEN_CHARSET , DEF_TOKEN_CHARSET );
		valSmsPROVIDER   = props.getProperty( PROP_SMS_PROVIDER  , DEF_SMS_PROVIDER );		
		valSmsATTRIBUTE  = props.getProperty( PROP_SMS_ATTRIBUTE , DEF_SMS_ATTRIBUTE );
		valSmsALTATTR    = props.getProperty( PROP_SMS_ALTATTR   , DEF_SMS_ALTATTR );
		valExpCOOKIE     = props.getProperty( PROP_EXP_COOKIE    , DEF_EXP_COOKIE );
		valExpATTRIBUTE  = props.getProperty( PROP_EXP_ATTRIBUTE , DEF_EXP_ATTRIBUTE );
		// The integer values are checked and parsed
		valInputLENGTH = getSafeIntegerValue( PROP_TOKEN_LENGTH, props.getProperty( PROP_TOKEN_LENGTH, DEF_TOKEN_LENGTH ) ); 		
		valExpTIME     = getSafeIntegerValue( PROP_EXP_TIME,     props.getProperty( PROP_EXP_TIME,     DEF_EXP_TIME ) );
		valSmsTIMEOUT  = getSafeIntegerValue( PROP_SMS_TIMEOUT,  props.getProperty( PROP_SMS_TIMEOUT,  DEF_SMS_TIMEOUT ) );
		try 
		{
			provider = getProvider( valSmsPROVIDER );
			logger.log( Level.FINE, "Created SMS Provider: "+provider.getName() );
			// validate config from provider paramdesc
			List<String> missing = new ArrayList<>();
			attrNames = new TreeMap<>();
			for ( SmsParameterDesc param : provider.getParameters() )
			{
				logger.log( Level.FINEST, "Provider param: "+param.getName() );
				if ( ! props.containsKey( param.getName() ) )
				{
					missing.add( param.getName() );
				}
				else if ( param.getType().equals( SmsParameterType.ATTRIBUTE ) )
				{
					attrNames.put( props.getProperty( param.getName() ), param.getName() );
				}
			}
			if ( ! missing.isEmpty() )
			{
				String missed = Arrays.toString( missing.toArray( new String[missing.size()] ) );
				throw new NIDPException( "Missing parameter"+(missing.size()>1 ?"s":"")+" for SMS Provider "+provider.getName()+": "+missed );
			}
			conf = new SmsConfig(props, provider.getParameters());
			provider.init( conf, debugMode );
		} catch (Exception e) {
			logger.log( Level.SEVERE, "Exception: "+e.getMessage() );
			throw new NIDPException(e);
		}
		sessionUser = getProperty("findSessionUser");
		logger.log( Level.FINE, "Done." );
	}

	/**
	 * Try to instantiate a SmsProvider object from the given classname
	 * @param classname
	 * @return
	 * @throws Exception
	 */
	private SmsProvider getProvider( String classname ) throws Exception
	{
		// Load the configured SMS provider
		if ( SmsProvider.class.isAssignableFrom( Class.forName( classname ) ) )
		{
			return (SmsProvider) Class.forName( classname ).newInstance();
		}
		throw new Exception("Class "+classname+" does not implement "+SmsProvider.class.getName() );
	}

	@Override
	public String getType()
	{
		return AuthnConstants.TOKEN;
	}

	@Override
	protected int doAuthenticate() 
	{
		localPrincipal = resolveUserPrincipal();
		if ( localPrincipal == null )
		{
			logger.log( Level.WARNING, "Could not resolve Principal, failing login" );
			return NOT_AUTHENTICATED;
		}
		logger.log( Level.INFO, "Logging in: "+localPrincipal.getUserIdentifier() );
		completeProviderConfigurationData();
		// Start authentication flow
		if ( isFirstCallAfterPrevMethod() )
		{
			SmsMessage smsMsgObject = createMessageObjectFromPrincipal();
			// If a delay value is present and cookie is present, return
			String cookieName = getCookieName( valExpCOOKIE, localPrincipal.getUserIdentifier() );
			Cookie ck = getCookie( m_Request.getCookies(), cookieName );
			if ( smsMsgObject.hasDelay() && ck != null && checkCookieValidity( ck ) )
			{
				logger.log(Level.FINE, "Cookie "+cookieName+" is present and valid, skipping authentication");
				setPrincipal(localPrincipal);
				return AUTHENTICATED;
			}
			else
			{
				// Clear the cookie and continue
				logger.log(Level.FINER, "Cookie "+cookieName+" is not present or not valid, clearing");
				clearCookie( ck );
			}
			return sendTokenAndPromptForVerification(smsMsgObject);
		}
		else
		{
			SmsMessage smsMsgObject = createMessageObjectFromSession();
			String token = m_Request.getParameter( valInputToken );
			// Detect if retry was pressed
			if ( m_Request.getParameter( valInputRETRY ) != null )
			{
				smsMsgObject.setSelectedNumber( m_Request.getParameter( valInputNUMBER ) );
				logger.log( Level.INFO, "Retry was selected, sending a new code to "+smsMsgObject.getSelectedNumber() );
				return sendTokenAndPromptForVerification(smsMsgObject);
			}
			// Check code that was sent
			logger.log(Level.FINE, String.format("Checking sent code '%s' against received code '%s'.", smsMsgObject.getToken(), token));
			if( smsMsgObject.validateToken( token ) )
			{
				logger.log(Level.FINE, String.format("Checking sent code '%s' against received code '%s'.", smsMsgObject.getToken(), token));
				placeCookieIfDelayRequested( m_Request.getParameter( valInputPostpone ), smsMsgObject.getDelay() );
				setPrincipal(localPrincipal);
				return AUTHENTICATED;
			}
			else if (isValidScratchCode(token))
			{
				logger.log(Level.FINE, String.format("Logged in using %s as a scratch code.", token));
				setPrincipal(localPrincipal);
				return AUTHENTICATED;				
			}
			else
			{
				logger.log( Level.WARNING, "codes did not match!" );
				prepareTokenVerificationPage(smsMsgObject);
				m_PageToShow.addAttribute( SmsConstants.ATTR_ERROR, SmsConstants.ERR_CODE_INVALID );
				return SHOW_JSP;
			}
		}
	}

	private boolean isValidScratchCode( String token )
	{
		Properties totpProperties = new Properties(TOTPConstants.getDefaults());
		totpProperties.putAll(m_Properties);
		try
		{
			Authenticator authenticator = new Authenticator(m_Properties, localPrincipal);
			if ( token.matches("\\d+" ) && authenticator.validateScratchCode( Integer.parseInt( token ) ) )
			{
				authenticator.persist();
				return true;
			}		
		}
		catch (TOTPException e)
		{
		}
		return false;
	}

	private void completeProviderConfigurationData()
	{
		if ( provider.needPrincipal() )
		{
			conf.addParam( SmsConfig.PRINCIPAL_DN, localPrincipal.getUserIdentifier() );
		}
		if ( attrNames.size() > 0 )
		{
			updateAttributeDataInConfig();
		}
		provider.update(conf);
	}

	private void updateAttributeDataInConfig()
	{
		logger.log( Level.FINER, "updating Principal attribute data" );
		// Empty all attributes first (prevent fake data)
		for ( Map.Entry<String, String> attrName : attrNames.entrySet() )
			conf.addParam( attrName.getValue(), null );
		// Fill information from LDAP
		Attributes attrs = getLdapAttributes( localPrincipal, attrNames.keySet() );
		if ( attrs != null )
		{
			NamingEnumeration<?> returnedAttrs = attrs.getAll();
			try {
				while ( returnedAttrs.hasMore() )
				{
					Attribute attr = (Attribute) returnedAttrs.next();
					conf.addParam( attrNames.get( attr.getID() ), attr.get() );
				}
			} catch (NamingException e) {
				logger.log( Level.WARNING, "error retrieving principal attributes: "+e.getExplanation() );
			}
		}
		else
			logger.log( Level.FINER, "no attributes returned!" );
	}

	private SmsMessage createMessageObjectFromPrincipal()
	{
		// Retrieve the delay until next authentication
		int delay = getDelayAttributeValue( localPrincipal );
		// find out if user has a (valid?) phone number and/or alternative number assigned
		String phoneNumber = getStringAttributeValue( localPrincipal, valSmsATTRIBUTE );
		String altPhoneNumber = valSmsALTATTR.isEmpty() ? "" : getStringAttributeValue( localPrincipal, valSmsALTATTR );
		SmsMessage smsMsgObject = new SmsMessage( phoneNumber, altPhoneNumber );
		smsMsgObject.setDelay( delay );
		return smsMsgObject;
	}

	private SmsMessage createMessageObjectFromSession()
	{
		// Get data from session
		String phoneNumber = (String) m_Request.getSession().getAttribute( SmsConstants.ATTR_NUMBER );
		String altPhoneNumber = (String) m_Request.getSession().getAttribute( SmsConstants.ATTR_NUMBER_ALT );
		Integer delay = (Integer) m_Request.getSession().getAttribute( SmsConstants.ATTR_DELAY );
		RandomCode sentAuthToken = (RandomCode) m_Request.getSession().getAttribute( SmsConstants.ATTR_TOKEN );
		// Return new token with all data
		return new SmsMessage(phoneNumber, altPhoneNumber).setDelay(delay).setToken(sentAuthToken);
	}

	private int sendTokenAndPromptForVerification(SmsMessage messageObject)
	{
		// Prepare the actual JSP page
		prepareTokenVerificationPage(messageObject);
		if ( ! messageObject.hasValidNumber() )
		{
			logger.log( Level.WARNING, "principal has no number!" );
			m_PageToShow.addAttribute( SmsConstants.ATTR_ERROR, SmsConstants.ERR_NO_NUMBER );
			return SHOW_JSP;
		}
		sendNewRandomCode(messageObject);
		return SHOW_JSP;
	}

	private void prepareTokenVerificationPage( SmsMessage messageObject )
	{
		m_PageToShow = new PageToShow( valInputJSP );
		m_PageToShow.addAttribute( NIDPConstants.ATTR_URL, getReturnURL() != null ? getReturnURL() : m_Request.getRequestURL().toString() );
		m_PageToShow.addAttribute( SmsConstants.ATTR_NUMBER, messageObject.getPrimaryPhone() );
		if ( messageObject.hasDelay() )
			m_PageToShow.addAttribute( SmsConstants.ATTR_DELAY, Integer.toString(messageObject.getDelay()) );
		if ( messageObject.hasSecondaryPhone() )
			m_PageToShow.addAttribute( SmsConstants.ATTR_NUMBER_ALT, messageObject.getSecondaryPhone() );
	}

	private void sendNewRandomCode( SmsMessage messageObject )
	{
		// create token with settings from params
		RandomCode authToken = new RandomCode( valInputCHARSET.toCharArray(), valInputLENGTH );
		messageObject.setToken( authToken );
		logger.log( Level.FINE, "Sending token: "+authToken.getCode() );
		if ( sendViaProvider( authToken.getCode(), messageObject.getSelectedNumber() ) )
		{
			logger.log( Level.FINE, "send success!" );
			m_Request.getSession().setAttribute( SmsConstants.ATTR_TOKEN, authToken );
			m_Request.getSession().setAttribute( SmsConstants.ATTR_NUMBER, messageObject.getSelectedNumber() );
			if ( messageObject.hasSecondaryPhone() )
			{
				m_Request.getSession().setAttribute( SmsConstants.ATTR_NUMBER_ALT, messageObject.getSecondaryPhone() );
			}
			if ( messageObject.hasDelay() )
			{
				m_Request.getSession().setAttribute( SmsConstants.ATTR_DELAY, messageObject.getDelay() );
			}
		}
		else
		{
			logger.log( Level.WARNING, "send failed!" );
			m_PageToShow.addAttribute( SmsConstants.ATTR_ERROR, SmsConstants.ERR_SEND_FAILED );
		}
	}

	/** 
	 * Send the message string to the given number string, using the configured {@link nl.idfocus.nam.sms.SmsProvider#send} method. 
	 * @param message
	 * @param number
	 * @return
	 */
	private boolean sendViaProvider( String message, String number )
	{
		if ( provider.ready() && number != null )
			return provider.send( message, number, valSmsTIMEOUT );
		return false;
	}

	private void placeCookieIfDelayRequested(String toggle, int delay)
	{
		logger.log( Level.FINER, "Checking cookie setting: "+toggle );
		if ( "on".equalsIgnoreCase( toggle ) )
		{
			// Prepare cookie and add to response
			Cookie ck = createCookie( valExpCOOKIE, localPrincipal.getUserIdentifier(), delay );
			logger.log( Level.FINEST, "Setting cookie: "+ck.getName() );
			m_Response.addCookie(ck);
		}
	}

	/**
	 * Clear the current user cookie by settings the value to null and the max age to 0. <br/>
	 * The cookie is then added to the HTTP response object.
	 * @param ck the cookie object to clear
	 */
	private void clearCookie(Cookie ck) 
	{
		if ( ck != null )
		{
			ck.setValue(null);
			ck.setMaxAge(0);
			m_Response.addCookie(ck);
		}
	}

	/**
	 * Check the validity of a cookie object in terms of lifetime and/or the timestamp contents.
	 * @param ck the cookie object to check
	 * @return true if the lifetime is greater than 0 or the timestamp contents is in the future, false otherwise
	 */
	private boolean checkCookieValidity(Cookie ck) 
	{
		logger.log( Level.FINER, "Checking cookie validity");
		if ( ck != null )
		{
			int lifetime = ck.getMaxAge();
			logger.log( Level.FINEST, "lifetime: "+lifetime );
			logger.log( Level.FINEST, "contents: "+ck.getValue() );
			boolean invalid = isDatePast( ck.getValue() );
			logger.log( Level.FINEST, "date past: "+invalid );
			if ( lifetime > 0 || !invalid )
			{
				return true;
			}
		}
		return false;
	}

	/**
	 * Retrieve the named cookie from the given list of cookies.
	 * @param cookies
	 * @param cookieName
	 * @return
	 */
	private Cookie getCookie(Cookie[] cookies, String cookieName) 
	{
		if ( cookies != null )
		{
			for ( Cookie ck : cookies )
			{
				if ( ck.getName().equals(cookieName) )
					return ck;
			}
		}
		return null;
	}

	private Cookie createCookie( String name, String uid, int delay ) 
	{
		String cname = getCookieName( name, uid );
		String contents = getExpirationDate(delay);
		Cookie result = new Cookie( cname, contents );
		result.setMaxAge( getSecondsUntilDelay(delay) );
		result.setSecure(true);
		logger.log( Level.FINER, "Created cookie "+result.getName()+" with age "+result.getMaxAge()+" and value "+result.getValue() );
		return result;
	}

	private String getCookieName( String prefix, String userid )
	{
		try
		{
			String uid = Sha256.toHashString(userid);
			return prefix+uid;
		} catch (Exception e) {
			logger.log( Level.WARNING, "Cannot generate unique cookie name: "+e.getMessage() );
		}
		return prefix;
	}

	/**
	 * Resolve the current NIDP principal object by any known means.
	 * @return principal object for the current user
	 */
	private NIDPPrincipal resolveUserPrincipal()
	{
		logger.log( Level.FINER, "getting principal from localauthentication class");
		NIDPPrincipal nidpprincipal = getPrincipal();
		if ( nidpprincipal == null )
		{
			logger.log( Level.FINEST, "getting principal from properties (contract)");
			nidpprincipal = (NIDPPrincipal) m_Properties.get("Principal");
			if ( nidpprincipal == null )
			{
				logger.log( Level.FINEST, "getting subject from session");
				if(sessionUser != null)
				{
					if( m_Session.isAuthenticated() )
					{
						NIDPSubject nidpsubject = m_Session.getSubject();
						NIDPPrincipal[] allNidpPrincipals = nidpsubject.getPrincipals();
						logger.log( Level.FINEST, "found "+allNidpPrincipals.length+" principal(s) in session subject");
						if(allNidpPrincipals.length == 1)
						{
							nidpprincipal = allNidpPrincipals[0];
							logger.log( Level.FINEST,  ( new StringBuilder() ).append("principal retrieved from authenticated session: ").append( nidpprincipal.getUserIdentifier() ).toString() );
						}
					}
					if(nidpprincipal == null)
						logger.log( Level.FINEST, "no single principal in session");
				}
			}
			else
			{
				logger.log( Level.FINEST, (new StringBuilder()).append("retrieved principal from properties: ").append(nidpprincipal.getUserIdentifier()).toString());
			}
		}
		else
		{
			logger.log( Level.FINEST, (new StringBuilder()).append("retrieved principal from localauthentication class: ").append(nidpprincipal.getUserIdentifier()).toString());
		}
		return nidpprincipal;
	}

	/**
	 * Check if the given date String in yyyyMMddHHmmssZ format is in the past.
	 * @param dateStr Date as a String in yyyyMMddHHmmssZ format
	 * @return true for in the past, false for in the future.
	 */
	private boolean isDatePast( String dateStr )
	{
		SimpleDateFormat format = new SimpleDateFormat( "yyyyMMddHHmmss'Z'" );
		Calendar cal = Calendar.getInstance();
		cal.setTimeZone( TimeZone.getTimeZone( "UTC" ) );
		Date today = cal.getTime();
		try {
			Date check = format.parse( dateStr );
			return today.after( check );
		} catch (ParseException e) {
			logger.log( Level.WARNING, "Date parsing exception: "+e.getMessage()+" for value "+dateStr+" at position "+e.getErrorOffset() );
		} catch (NullPointerException e) {
			logger.log( Level.WARNING, "Date parsing exception: "+e.getMessage()+" for value "+dateStr );
		}
		return false;
	}

	/**
	 * Get the number of seconds until midnight as an integer value for use in cookies. 
	 * @return int representing the number of seconds until midnight
	 */
	private int getSecondsUntilDelay( int delay )
	{
		Calendar c = Calendar.getInstance();
		Date now = new Date();
		c.add(Calendar.DATE, delay );
		c.set(Calendar.HOUR_OF_DAY, 0);
		c.set(Calendar.MINUTE, 0);
		c.set(Calendar.SECOND, 0);
		c.set(Calendar.MILLISECOND, 0);
		Long howMany = ( c.getTimeInMillis()-now.getTime() ) / 1000 ;
		return howMany.intValue();
	}

	/**
	 * Get the date that the current authentication delay will expire. Uses UTC.
	 * @return Date as a String in yyyyMMddHHmmssZ format.
	 */
	private String getExpirationDate( int delay )
	{
		Calendar cal = Calendar.getInstance();
		cal.setTimeZone( TimeZone.getTimeZone( "UTC" ) );
		cal.set( Calendar.HOUR_OF_DAY , 23 );
		cal.set( Calendar.MINUTE , 59 );
		cal.set( Calendar.SECOND , 59 );
		cal.add( Calendar.DATE, delay );
		SimpleDateFormat format = new SimpleDateFormat( "yyyyMMddHHmmss'Z'" );
		return format.format( cal.getTime() );
	}

	private int getDelayAttributeValue( NIDPPrincipal princ ) 
	{
		String value = getStringAttributeValue(princ, valExpATTRIBUTE);
		if( value.isEmpty() )
			return valExpTIME;
		return getSafeIntegerValue( "", value );
	}

	/**
	 * Retrieve a property value and try to parse it as an Integer.
	 * @param property
	 * @param value
	 * @return the int value of the string parameter, or '0' if it cannot be done.
	 */
	private int getSafeIntegerValue( String property, String value )
	{
		try
		{
			return Integer.parseInt(value);
		} catch (NumberFormatException e) {
			logger.log(Level.WARNING, "Could not determine numeric value for '"+property+"', returning 0");
			return 0;
		}
	}

	/**
	 * Method to retrieve the string value of a given attribute of the given NIDP principal object. <br/>
	 * @param princ the principal whose number to read
	 * @return the first encountered attribute value
	 */
	private String getStringAttributeValue( NIDPPrincipal princ, String attributeName )
	{
		try {
			Attribute attribute = getLdapAttribute( princ, attributeName );
			if ( attribute.size() > 0 )
			{
				logger.log( Level.FINEST, attribute.size()+" value"+(attribute.size()>1?"s":"")+" found"+(attribute.size()>1?", returning first one":""));
				Object value = attribute.get();
				if ( value != null && value instanceof String )
				{
					return (String)value;
				}
			}
			else
			{
				logger.log( Level.FINEST, "no values found for "+attributeName);
			}
		} catch (NamingException e) {
			logger.log( Level.FINEST,  "NamingException getting values for "+attributeName+": "+e.getExplanation() );
		}
		return "";
	}

	private Attribute getLdapAttribute( NIDPPrincipal princ, String attributeName )
	{
		UserAuthority ua = princ.getAuthority();
		logger.log( Level.FINEST, "getting attribute: "+attributeName );
		Attributes attrs = ua.getAttributes( princ , new String[] { attributeName } );
		logger.log( Level.FINEST, "getting attribute");
		Attribute result = attrs.get( attributeName );
		if ( result == null )
		{
			logger.log(Level.FINEST, "Attribute "+attributeName+" not found." );
			result = new BasicAttribute(attributeName);
		}
		return result;
	}

	private Attributes getLdapAttributes( NIDPPrincipal princ, Set<String> attributeNames ) 
	{
		String[] attributes = attributeNames.toArray( new String[ attributeNames.size() ] );
		try {
			UserAuthority ua = localPrincipal.getAuthority();
			logger.log( Level.FINEST, String.format("getting principal attributeset for %s object", princ.getUserIdentifier() ));
			Attributes attrs = ua.getAttributes( princ , attributes );
			logger.log( Level.FINEST, "returning attribute set");
			return attrs;
		} catch (Exception e) {
			logger.log( Level.FINEST, String.format("Exception '%s' encountered while retrieving attributes.", e.getMessage()) );
		}
		return null;
	}


}
