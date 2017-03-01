package nl.idfocus.nam.authentication;

import java.util.ArrayList;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.novell.nidp.authentication.AuthnConstants;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.logging.NIDPLog;
import com.novell.nidp.logging.NIDPLogDecorators;

/**
 * The <b>Deny</b> Authentication Class always returns a failed authentication to the IDP. <br/>
 * This class may be used as fallback for other classes such as the <code>Kerberos</code> module when further authentication is undesired.
 * </p>
 * 
 * @author mvreijn@idfocus.nl
 * @version Tested on NAM 4.x
 */
public class Deny extends LocalAuthenticationClass 
{

	public Deny(Properties props, ArrayList<UserAuthority> stores) 
	{
		super(props, stores);
	}

	@Override
	public String getType() 
	{
		return AuthnConstants.OTHER;
	}

	@Override
	protected int doAuthenticate() 
	{
		Logger log = NIDPLog.getAppLog();
		if ( NIDPLog.isLoggable(log, Level.INFO))
			log.log(Level.INFO, "Deny Authentication", new NIDPLogDecorators("IDFocus#", NIDPLogDecorators.AMDEVICE_PREFIX, NIDPLogDecorators.AMAUTH_PREFIX));
		return NOT_AUTHENTICATED;
	}

}
