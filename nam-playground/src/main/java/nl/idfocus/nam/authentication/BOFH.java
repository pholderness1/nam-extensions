package nl.idfocus.nam.authentication;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.novell.nidp.authentication.AuthnConstants;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.logging.NIDPLog;

/**
 * This is an example authentication class that is/was used for training and demonstration purposes.<br/>
 * Its heritage should be obvious to those in the know, all others... don't call.
 * @author IDFocus B.V. (mvreijn@idfocus.nl)
 *
 */
public class BOFH extends LocalAuthenticationClass 
{

	/**
	 * <p>
	 * The constructor for authentication classes receives a list of properties that contain combined
	 * settings from the <i>class and method</i> configuration in the Administration Console.
	 * </p><p>
	 * Next to those strings, the {@link java.util.Properties Properties} argument contains <i>objects</i> 
	 * such as the {@link com.novell.nidp.NIDPPrincipal NIDPPrincipal} that is logging in, and a reference 
	 * to the authentication request object. These should be retrieved using underlying 
	 * {@link java.util.HashTable HashTable} methods.
	 * </p>
	 * @param props
	 * @param stores
	 */
	public BOFH(Properties props, ArrayList<UserAuthority> stores) 
	{
		super(props, stores);
	}

	/**
	 * The {@link #getType()} method must return the type of authentication that this module provides. <br/>
	 * Usually one of {@link AuthnConstants#PASSWORD}, {@link AuthnConstants#TOKEN}, {@link AuthnConstants#X509} or {@link AuthnConstants#OTHER}.
	 */
	@Override
	public String getType() 
	{
		return AuthnConstants.OTHER;
	}

	/**
	 * The {@link #doAuthenticate()} method is the one you really need to customize in order to make your class work. <br/>
	 * In this case it also uses the internal IDP logger, very convenient since the logging level will now be controllable through the NAM Admin Console.<br/>
	 */
	@Override
	protected int doAuthenticate() 
	{
		Logger log = NIDPLog.getAppLog();
		// Optionally use the isLoggable() call
		if ( NIDPLog.isLoggable(log, Level.INFO) )
			log.log(Level.INFO, "Authenticate BOFH");
		if ( feelLikeIt() )
			return AUTHENTICATED;
		else
			return NOT_AUTHENTICATED;
	}

	/**
	 * Give users a 50% chance of getting through. That should teach'em!
	 * @return Simon says maybe
	 */
	private boolean feelLikeIt()
	{
		return new SecureRandom().nextBoolean();
	}

}
