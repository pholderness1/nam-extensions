package nl.idfocus.nam.authentication;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.authentication.AuthnConstants;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.common.authority.UserAuthority;

import nl.idfocus.nam.util.ExistingPrincipalResolver;
import nl.idfocus.nam.util.LogFormatter;

/**
 * This authentication class can check if a user has previously been
 * authenticated (i.e. if we are in an authenticated session) and redirect to a
 * configured contract id if this is not the case.
 */
public class ContractDependency extends LocalAuthenticationClass
{

	private static final Logger	logger				= LogFormatter
			.getConsoleLogger(ContractDependency.class.getName());

	private static final String	PROP_CONTRACT_ID	= "ContractId";
	private final String		contractId;

	private static final String PKGBUILD = ContractDependency.class.getPackage().getImplementationVersion();

	public ContractDependency(Properties props, ArrayList<UserAuthority> stores)
	{
		super(props, stores);
		logger.log( Level.INFO, "Contract Dependency Authentication Class build "+PKGBUILD+" (c) IDFocus B.V. <info@idfocus.nl>" );
		contractId = props.getProperty(PROP_CONTRACT_ID);
	}

	@Override
	public String getType()
	{
		return AuthnConstants.OTHER;
	}

	@Override
	protected int doAuthenticate()
	{
		logger.log(Level.INFO, "Checking for previous authentication");
		NIDPPrincipal currentPrincipal = ExistingPrincipalResolver.resolveUserPrincipal(this,
				m_Properties, m_Session);
		if (currentPrincipal == null)
		{
			logger.log(Level.INFO, "No principal found, redirecting to " + contractId);
			return redirectToContract();
		}
		logger.log(Level.INFO, "A principal was already logged in");
		return AUTHENTICATED;
	}

	private int redirectToContract()
	{
		String returl = buildReturnURL();
		String authurl = buildAuthenticationURL(returl);
		try
		{
			m_Response.sendRedirect(authurl);
		}
		catch (IOException e)
		{
			logger.log(Level.SEVERE, "Redirect to dependency failed: " + e.getMessage());
			return NOT_AUTHENTICATED;
		}
		return HANDLED_REQUEST;
	}

	private String buildAuthenticationURL(String returl)
	{
		StringBuilder sb = new StringBuilder();
		sb.append(m_Request.getRequestURI()).append("?").append("id=").append(contractId)
				.append("&target=").append(returl);
		return sb.toString();
	}

	private String buildReturnURL()
	{
		String returl = getReturnURL();
		logger.log(Level.INFO, "URL to return to after identifying user: " + returl);
		try
		{
			returl = URLEncoder.encode(getReturnURL(), "UTF-8");
		}
		catch (UnsupportedEncodingException e)
		{
			logger.log(Level.SEVERE, "URL Encoding failed: " + e.getMessage());
			throw new IllegalStateException(e);
		}
		return returl;
	}
}
