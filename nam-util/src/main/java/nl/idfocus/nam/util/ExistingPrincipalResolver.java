package nl.idfocus.nam.util;

import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.NIDPSession;
import com.novell.nidp.NIDPSubject;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;

public class ExistingPrincipalResolver
{
	private static final Logger LOGGER = LogFormatter
			.getConsoleLogger(ExistingPrincipalResolver.class.getName());

	private ExistingPrincipalResolver()
	{
		// Hide constructor
	}

	/**
	 * Resolve the current NIDP principal object by any known means.
	 * 
	 * @param authenticationClass
	 * @param properties
	 * @param session
	 * @return principal object for the current user
	 */
	public static NIDPPrincipal resolveUserPrincipal(LocalAuthenticationClass authenticationClass,
			Properties properties, NIDPSession session)
	{
		LOGGER.log(Level.FINE, "getting principal from localauthentication class");
		NIDPPrincipal principal = authenticationClass.getPrincipal();
		if (principal == null)
		{
			LOGGER.log(Level.FINE, "getting principal from properties (contract)");
			principal = (NIDPPrincipal) properties.get("Principal");
			if (principal == null)
			{
				principal = ExistingPrincipalResolver.getPrincipalFromSession(session);
			}
			else
			{
				LOGGER.log(Level.INFO,
						(new StringBuilder()).append("retrieved principal from properties: ")
								.append(principal.getUserIdentifier()).toString());
			}
		}
		else
		{
			LOGGER.log(Level.INFO,
					(new StringBuilder())
							.append("retrieved principal from localauthentication class: ")
							.append(principal.getUserIdentifier()).toString());
		}
		return principal;
	}

	private static NIDPPrincipal getPrincipalFromSession(NIDPSession session)
	{
		LOGGER.log(Level.FINE, "getting principal from session");
		if (session == null)
		{
			return null;
		}

		NIDPPrincipal principal = null;
		if (session.isAuthenticated())
		{
			NIDPSubject nidpsubject = session.getSubject();
			NIDPPrincipal[] allNidpPrincipals = nidpsubject.getPrincipals();
			LOGGER.log(Level.FINE,
					"found " + allNidpPrincipals.length + " principal(s) in session subject");
			if (allNidpPrincipals.length == 1)
			{
				principal = allNidpPrincipals[0];
				LOGGER.log(Level.INFO,
						(new StringBuilder())
								.append("principal retrieved from authenticated session: ")
								.append(principal.getUserIdentifier()).toString());
			}
		}
		if (principal == null)
			LOGGER.log(Level.FINE, "no single principal in session");
		return principal;
	}
}
