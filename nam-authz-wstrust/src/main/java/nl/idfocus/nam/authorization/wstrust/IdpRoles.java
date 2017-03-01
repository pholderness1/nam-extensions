package nl.idfocus.nam.authorization.wstrust;

import java.util.logging.Logger;

import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.common.util.NIDPRoles;
import com.novell.nidp.localconfig.NIDPLocalConfigUtil;
import com.novell.nidp.logging.NIDPLog;
import com.novell.nidp.wstrust.authorization.PolicyValidator;

public class IdpRoles implements PolicyValidator
{
	public static final String	ACTAS		= "ActAs";
	public static final String	ONBEHALFOF	= "OnBehalfOf";
	public static final String	ISSUE		= "Issue";
	public static final String	VALIDATE	= "Validate";

	private final Logger		logger;
	private final NIDPRoles		roles;
	private final String		actAsRole;
	private final String		onBehalfOfRole;
	private String[]			principalRoles;

	public IdpRoles()
	{
		logger = NIDPLog.getAppLog();
		roles = new NIDPRoles();
		actAsRole = determineRoleValue("WSTRUST_AUTHORIZATION_ROLE_ACTAS", ACTAS);
		onBehalfOfRole = determineRoleValue("WSTRUST_AUTHORIZATION_ROLE_ONBEHALFOF", ONBEHALFOF);
		logger.finer(String.format(
				"Created IdpRoles authZ module with ActAs role %s and OnBehalfOf role %s.",
				actAsRole, onBehalfOfRole));
	}

	@Override
	public boolean evaluate(String something, String authzType)
	{
		logger.fine(String.format("evaluate() called for type %s with parameter %s.", authzType,
				something));
		if (ACTAS.equalsIgnoreCase(authzType))
		{
			return evaluateActAs(something);
		}
		if (ONBEHALFOF.equalsIgnoreCase(authzType))
		{
			return evaluateOnBehalfOf(something);
		}
		if (ISSUE.equalsIgnoreCase(authzType))
		{
			return true;
		}
		return VALIDATE.equalsIgnoreCase(authzType);
	}

	private boolean evaluateOnBehalfOf(String something)
	{
		for (String role : principalRoles)
		{
			if (onBehalfOfRole.equalsIgnoreCase(role))
				return true;
		}
		return false;
	}

	private boolean evaluateActAs(String something)
	{
		for (String role : principalRoles)
		{
			if (actAsRole.equalsIgnoreCase(role))
				return true;
		}
		return false;
	}

	private String determineRoleValue(String property, String alternative)
	{
		String role = NIDPLocalConfigUtil.getValue(property);
		if (role == null || role.isEmpty())
			return alternative;
		return role;
	}

	@Override
	public void init(NIDPPrincipal principal)
	{
		logger.finer("IdpRoles authZ initializing for principal "+principal.getUserIdentifier());
		this.principalRoles = roles.getRoles(principal);
	}

}
