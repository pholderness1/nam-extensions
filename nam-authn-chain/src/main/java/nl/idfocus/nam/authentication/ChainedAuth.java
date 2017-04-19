package nl.idfocus.nam.authentication;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import nl.idfocus.nam.util.LogFormatter;

import com.novell.nidp.NIDPException;
import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.authentication.AuthClassDefinition;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.common.authority.UserAuthority;

/**
 * <b>Custom Authentication class for NetIQ Access Manager</b><br/>
 * <p>
 * The ChainedAuth class allows you to specify a chain of multiple subclasses to be tried in succession, 
 * supporting two modes. <br/>
 * In 'AND' mode, this class requires all configured subclasses to succeed, while in 'OR' mode the 
 * first subclass that succeeds results in a successful authentication. 
 * The latter behavior is similar to PAM when using the <i>"optional"</i> control. <br/>
 * </p><p>
 * Authentication classnames to be tried may be entered in this class' properties or in the method 
 * properties (if this class is used multiple times) using 
 * <pre>Class_#  &lt;classname></pre> 
 * where # is a number and indicates the order of execution. <br/>
 * The following classes may be specified using their short name: 
 * <ul>
 * <li>AliasUserPasswordClass</li>
 * <li>BasicClass</li>
 * <li>ClientIntegrityCheckClass</li>
 * <li>KerberosClass</li>
 * <li>NMASAuthClass</li>
 * <li>NPOrRadiusOrX509Class</li>
 * <li>OpenIDClass</li>
 * <li>PasswordClass</li>
 * <li>PasswordFetchClass</li>
 * <li>PersistenceAuthClass</li>
 * <li>ProtectedBasicClass</li>
 * <li>ProtectedPasswordClass</li>
 * <li>ProtectedRadiusClass</li>
 * <li>RadiusClass</li>
 * <li>RiskBasedAuthClass</li>
 * <li>SocialAuthClass</li>
 * <li>TOTPClass</li>
 * <li>X509Class</li>
 * <li>ChainedAuth <i>(this class)</i></li>
 * </ul>
 * Any other class, including custom classes, must be specified using the full Java classname. <br/>
 * </p><p>
 * Properties for all configured (chained) authentication classes must be specified here as well, using the <i>prefix</i>
 * <pre>Class_#_  &lt;propertyname></pre>
 * where # is the number that corresponds to the authentication class that the property belongs to.<br/>
 * <b>NOTE</b> Unprefixed properties are passed on to <i>all</i> classes. 
 * </p><p>
 * After initialization of the configured classes and passing properties to them, the list of classes is executed at login time until one succeeds, or until all have failed. <br/>
 * </p>
 * @author IDFocus B.V. (mvreijn@idfocus.nl)
 * @version Tested on NetIQ Access Manager 4.0.x, 4.1.x and 4.2
 */
public class ChainedAuth extends LocalAuthenticationClass 
{
	private static final Logger logger   = LogFormatter.getConsoleLogger( ChainedAuth.class.getName() );
	private static final Level  loglevel = Level.INFO;
	private static final Level  dbglevel = Level.FINE;
	private static final Level  errlevel = Level.SEVERE;

	/**
	 * By setting this property name on the class or method, the debug mode may be enabled. 
	 * This overrides the default value of 'false'.
	 */
	private static final String PROP_DEBUG   = "DEBUG";
	/**
	 * By setting this property name on the class or method, the execution mode may be specified. <br/>
	 * Valid values are:
	 * <ul>
	 * <li>AND (All classes have to succeed, like a regular contract)</li>
	 * <li>OR (Only one class needs to succeed, like PAM 'optional')</li>
	 * </ul>
	 * The default value is "OR" if this setting is not specified.
	 */
	private static final String PROP_MODE    = "MODE";
	/** Constant to specify <i>AND</i> mode, implying that all classes have to succeed for a successful authentication. */
	private static final String PROP_MODE_AND = "AND";
	/** Constant to specify <i>OR</i> mode, implying that the first class that succeeds triggers a successful authentication. */
	private static final String PROP_MODE_OR  = "OR";
	/** The regular expression that matches the prefix <i>Class_</i> for class-specific properties. */
	private static final String CLASS_REGEX  = "Class_\\d";
	private static final int    CLASS_SUBSTR = 7;
	private static final int    PROP_SUBSTR  = 8;

	private int authCount;
	private final boolean debugMode;
	private final String authMode;
	private final Map<String,List<String>> propNames;
	private final Properties genProps;
	private final List<String> classProps;
	private LocalAuthenticationClass currentClass;
	private boolean callNewClass;
	private boolean firstCall;

	private static final String PKGBUILD = ChainedAuth.class.getPackage().getImplementationVersion();

	public ChainedAuth(Properties props, ArrayList<UserAuthority> stores) 
	{
		super(props, stores);
		logger.log( loglevel, "Chained Authentication Class build "+PKGBUILD+" (c) IDFocus B.V. <info@idfocus.nl>" );
		// Determine debug setting
		debugMode = Boolean.parseBoolean( props.getProperty( PROP_DEBUG, "false" ) );
		if ( debugMode )
		{
			LogFormatter.setLoggerDebugMode(logger);
		}
		// Process settings
		List<String> authNames = new ArrayList<>();
		propNames = new HashMap<>();
		genProps  = new Properties();
		// Read properties
		for ( Object oKey : props.keySet() )
		{
			String key = (String)oKey;
			if ( key.matches( CLASS_REGEX ) )
			{
				logger.log(dbglevel, "[DBG] Recognized class parameter "+key+".");
				authNames.add( key );
			}
			else if ( key.matches( CLASS_REGEX+"_.+") )
			{
				logger.log(dbglevel, "[DBG] Recognized class property "+key+".");
				String classPrefix = key.substring(0, CLASS_SUBSTR);
				if ( ! propNames.containsKey(classPrefix) )
					propNames.put( classPrefix, new ArrayList<String>() );
				propNames.get( classPrefix ).add(key);
			}
			// allow debug (and NAM internals) to be passed down
			else if ( ! key.equals( PROP_MODE ) )
			{
				logger.log(dbglevel, "[DBG] Recognized general property "+key+".");
				try
				{
					genProps.put( key, props.get(key) );
				}
				catch (NullPointerException e) 
				{
					logger.log( errlevel, "NPE for key; "+key );
				}
			}
		}
		// Initialize the MODE parameter
		authMode = props.getProperty( PROP_MODE, PROP_MODE_OR );
		// Sorting results in numeric sort of last digit
		Collections.sort( authNames );
		classProps = validateClasses( authNames, propNames, genProps );
		// Defaults
		firstCall = true;
		callNewClass = false;
		currentClass = null;
		logger.log( loglevel, "Done." );
	}

	@Override
	protected int doAuthenticate() 
	{
		int authStatus = NOT_AUTHENTICATED;
		if ( firstCall )
		{
			firstCall = false;
			authCount = 0;
			callNewClass = true;
			logger.log( loglevel, String.format( "Starting Chained Authentication in %s mode.", authMode ) );
		}
		else
		{
			logger.log( loglevel, String.format( "Resuming Chained Authentication in %s mode.", authMode ) );
		}
		try
		{
			if ( PROP_MODE_AND.equalsIgnoreCase( authMode ) )
			{
				authStatus = authenticateAndMode();
			}
			else if ( PROP_MODE_OR.equalsIgnoreCase( authMode ) )
			{
				authStatus = authenticateOrMode();
			}
		}
		catch(NIDPException e)
		{
			authStatus = NOT_AUTHENTICATED;
		}
		return authStatus;
	}

	/**
	 * Try all classes in order, return if one fails or all succeed
	 * @return authentication status of the current class in the stack.
	 */
	private int authenticateAndMode() throws NIDPException
	{
		int authStatus = NOT_AUTHENTICATED;
		while( authCount < classProps.size() )
		{
			/* 
			 * add new principal information to subsequent children
			 * initialize new children with the correct setting for first call
			 */ 
			if ( callNewClass || currentClass == null )
			{
				String classProp = classProps.get(authCount);
				logger.log( loglevel, String.format( "Trying class %s.", authCount ) );
				// Instantiate new class
				currentClass = createClass( classProp, propNames.get(classProp), genProps );
			}
			// Initialize the request and authenticate
			currentClass.initializeRequest( m_Request, m_Response, m_Session, m_SessionData, callNewClass, getReturnURL() );
			authStatus = currentClass.authenticate();
			if ( authStatus == NOT_AUTHENTICATED )
			{
				logger.log( dbglevel, String.format( "Class %s authentication failed.", authCount ) );
				callNewClass = true;
				return authStatus;
			}
			else if ( authStatus == AUTHENTICATED )
			{
				logger.log( dbglevel, String.format( "Class %s authentication succeeded.", authCount ) );
				updatePrincipal( currentClass, false );
				callNewClass = true;
				authCount++;
			}
			else if ( authStatus == SHOW_JSP )
			{
				logger.log( dbglevel, String.format( "Class %s requires interaction.", authCount ) );
				m_PageToShow = currentClass.getPageToShow();
				callNewClass = false;
				return authStatus;
			}
			else
			{
				if ( authStatus == PWD_EXPIRING )
				{
					logger.log( dbglevel,  String.format( "Class %s authentication succeeded conditionally (password expired).", authCount ) );
					updatePrincipal( currentClass, true );
					callNewClass = true;
					authCount++;
				}
				else
				{
					logger.log( dbglevel, String.format( "Class %s authentication failed with status %s.", authCount, authStatus ) );
					callNewClass = true;
					return authStatus;
				}
			}
		}
		return authStatus;		
	}

	/**
	 * Try all classes in order, return if one succeeds
	 * @return authentication status of the current class in the stack.
	 */
	private int authenticateOrMode() throws NIDPException
	{
		int authStatus = NOT_AUTHENTICATED;
		while( authCount < classProps.size() )
		{
			if ( callNewClass || currentClass == null )
			{
				String classProp = classProps.get(authCount);
				logger.log( loglevel, String.format( "Trying class %s.", authCount ) );
				// Instantiate new class
				currentClass = createClass( classProp, propNames.get(classProp), genProps );
			}
			currentClass.initializeRequest( m_Request, m_Response, m_Session, m_SessionData, callNewClass, getReturnURL() );
			authStatus = currentClass.authenticate();
			if ( authStatus == NOT_AUTHENTICATED )
			{
				logger.log( dbglevel, String.format( "Class %s authentication failed.", authCount ) );
				callNewClass = true;
				authCount++;
			}
			else if ( authStatus == AUTHENTICATED )
			{
				logger.log( dbglevel, String.format( "Class %s authentication succeeded.", authCount ) );
				updatePrincipal( currentClass, false );
				callNewClass = true;
				return authStatus;
			}
			else if ( authStatus == SHOW_JSP )
			{
				logger.log( dbglevel, String.format( "Class %s requires interaction.", authCount ) );
				m_PageToShow = currentClass.getPageToShow();
				callNewClass = false;
				return authStatus;
			}
			else
			{
				if ( authStatus == PWD_EXPIRING )
				{
					logger.log( dbglevel, String.format( "Class %s authentication succeeded conditionally (password expired).", authCount ) );
					updatePrincipal( currentClass, true );
					callNewClass = true;
					return authStatus;
				}
				else
				{
					logger.log( dbglevel, String.format( "Class %s authentication failed with status %s.", authCount, authStatus ) );
					callNewClass = true;
					authCount++;
				}
			}
		}
		return authStatus;		
	}

	/**
	 * Update the various principal settings.
	 * @param clazz the authentication class object to retrieve the Principal from
	 * @param expired whether or not to retrieve the expired Principal
	 */
	private void updatePrincipal( LocalAuthenticationClass clazz, boolean expired )
	{
		if ( expired )
		{
			m_PasswordException = clazz.getPasswordException();
			m_ExpiredPrincipal = clazz.getExpiredPrincipal();
		}
		else
		{
			m_Credentials = clazz.getCredentials();			
		}
		NIDPPrincipal pr = clazz.getPrincipal();
		logger.log( dbglevel, String.format( "Class %s identified principal %s.", clazz.getClass().getName(), pr == null ? "*none*" : pr.getUserIdentifier() ) );
		setPrincipal( pr );
		m_Properties.put( "Principal", pr );
		genProps.put( "Principal", pr );
	}

	private List<String> validateClasses( List<String> authNames, Map<String,List<String>> authProps, Properties genProps ) 
	{
		logger.log(loglevel, "Checking "+authNames.size()+" authentication classes.");
		List<String> results = new ArrayList<>();
		for ( String name : authNames )
		{
			String className = m_Properties.getProperty(name);
			Properties localClassProps = mergeProperties(m_Properties, authProps.get(name), genProps);
			try {
				KnownClasses builtin = KnownClasses.valueOf(className);
				logger.log(dbglevel, "[DBG] Recognized "+className+" as builtin.");
				className = builtin.getClassName();
			}
			catch(IllegalArgumentException e) {}
			try {
				logger.log(dbglevel, "[DBG] Instantiating authentication class "+className+"...");
				AuthClassDefinition rawDefinition = new AuthClassDefinition( "ChainedAuth", className, localClassProps );
		        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, localClassProps);
		        // Succeeded instantiating the class, add to valid classes
		        if ( newClass != null )
		        	results.add( name );
				logger.log(dbglevel, "[DBG] Done.");
			} catch (NIDPException e) {
				logger.log(errlevel, "Error "+e.getErrorID()+": "+e.getMessage()+" for class "+className+"." );
			}
		}
		return results;
	}

	/**
	 * Instantiate a new authentication class object with a set of generic and specific properties. 
	 * @param classProp
	 * @param authProps
	 * @param genProps
	 * @return
	 */
	private LocalAuthenticationClass createClass( String classProp, List<String> authProps, Properties genProps ) throws NIDPException
	{
		String className = m_Properties.getProperty(classProp);
		logger.log(loglevel, String.format( "Creating authentication class %s.", className ) );
		Properties localClassProps = mergeProperties( m_Properties, authProps, genProps );
		try {
			KnownClasses builtin = KnownClasses.valueOf(className);
			logger.log(dbglevel, "[DBG] Recognized "+className+" as builtin.");
			className = builtin.getClassName();
		}
		catch(IllegalArgumentException e) {}
		try {
			logger.log(dbglevel, "[DBG] Instantiating authentication class "+className+"...");
			AuthClassDefinition rawDefinition = new AuthClassDefinition( "ChainedAuth", className, localClassProps );
	        LocalAuthenticationClass newClass = rawDefinition.getInstance(m_UserStores, localClassProps);
			logger.log(dbglevel, "[DBG] Done.");
			return newClass;
		} catch (NIDPException e) {
			logger.log(errlevel, "Error "+e.getErrorID()+": "+e.getMessage()+" for class "+className+"." );
			throw e;
		}
	}

	/**
	 * Create a new Properties object which contains all keys from genProps, 
	 * and a subset of keys from allProps, where the key is trimmed to reflect the real name. 
	 * @param allProps
	 * @param propNames
	 * @param genProps
	 * @return
	 */
	private Properties mergeProperties( Properties allProps, List<String> propNames, Properties genProps )
	{
		Properties result = new Properties();
		logger.log(dbglevel, String.format( "[DBG] Adding %s general properties.", genProps.size() ) );
		result.putAll( genProps );
		if ( propNames != null )
		{
			for ( String name : propNames )
			{
				String shortName = name.substring(PROP_SUBSTR);
				logger.log(dbglevel, String.format( "[DBG] Adding %s as specific property.", shortName ) );
				Object old = result.put( shortName, allProps.get(name) );
				if ( old != null )
					logger.log(dbglevel, String.format( "[DBG] Replaced existing value %s of property %s with value %s.", old.toString(), shortName, allProps.get(name) ) );
			}
		}
		logger.log(dbglevel, String.format( "[DBG] Created a set of %s properties.", result.size() ) );
		return result;
	}

	/**
	 * These are the known classes from a vanilla NAM 4.1 installation. <br/>
	 * Also contains 'self', that is: ChainedAuth is a shortcut for this class. 
	 * @author mvreijn
	 *
	 */
	private enum KnownClasses
	{
		AliasUserPasswordClass    ("com.novell.nidp.authentication.local.AliasUserPasswordClass"),
		BasicClass                ("com.novell.nidp.authentication.local.BasicClass"),
		ClientIntegrityCheckClass ("com.novell.nidp.authentication.local.ClientIntegrityCheckClass"),
		KerberosClass          ("com.novell.nidp.authentication.local.KerberosClass"),
		NMASAuthClass          ("com.novell.security.nmas.nidp.NMASAuthClass"),
		NPOrRadiusOrX509Class  ("com.novell.nidp.authentication.local.NPOrRadiusOrX509Class"),
		OpenIDClass            ("com.novell.nidp.authentication.local.OpenIDClass"),
		PasswordClass          ("com.novell.nidp.authentication.local.PasswordClass"),
		PasswordFetchClass     ("com.novell.nidp.authentication.local.PasswordFetchClass"),
		PersistenceAuthClass   ("com.novell.nidp.authentication.local.PersistenceAuthClass"),
		ProtectedBasicClass    ("com.novell.nidp.authentication.local.ProtectedBasicClass"),
		ProtectedPasswordClass ("com.novell.nidp.authentication.local.ProtectedPasswordClass"),
		ProtectedRadiusClass   ("com.novell.nidp.authentication.local.ProtectedRadiusClass"),
		RadiusClass            ("com.novell.nidp.authentication.local.RadiusClass"),
		RiskBasedAuthClass     ("com.novell.nam.nidp.risk.RiskBasedAuthenticationClass"),
		SocialAuthClass        ("com.novell.nidp.authentication.local.SocialAuthClass"),
		TOTPClass              ("com.novell.nidp.authentication.local.TOTPAuthenticationClass"),
		X509Class              ("com.novell.nidp.authentication.local.X509Class"),
		ChainedAuth            ( nl.idfocus.nam.authentication.ChainedAuth.class.getName() ),
		;

		private String className;

		private KnownClasses( String className ) 
		{
			this.className = className;
		}

		public String getClassName()
		{
			return this.className;
		}
	}
}
