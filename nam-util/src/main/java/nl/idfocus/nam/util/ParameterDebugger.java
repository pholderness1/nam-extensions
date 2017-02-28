package nl.idfocus.nam.util;

import java.io.PrintStream;
import java.util.Enumeration;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class ParameterDebugger
{

	private PrintStream stream;
	private Logger log;
	private final boolean useLogger;

	private ParameterDebugger( PrintStream stream, Logger log )
	{
		this.stream = stream;
		this.log = log;
		if( log == null )
			useLogger = false;
		else
			useLogger = true;
	}

	public void showSession( HttpSession session )
	{
		print( "Showing session attributes");
		if( session != null )
		{
			Enumeration<?> attributes = session.getAttributeNames();
			while (attributes.hasMoreElements())
			{
				String attrname = (String) attributes.nextElement();
				Object attrvalue = session.getAttribute(attrname);
				print( "Attribute: " + attrname + " with value: " + attrvalue);
			}			
		}
	}

	public void showParameters(Map<?, ?> parameters)
	{
		print( "Showing received parameters");
		for (Map.Entry<?, ?> entry : parameters.entrySet())
		{
			print("Parameter: " + entry.getKey() + " with value: " + entry.getValue());
		}
	}

	public void showAttributes( HttpServletRequest request)
	{
		print("Showing received attributes");
		Enumeration<?> attributeNames = request.getAttributeNames();
		while (attributeNames.hasMoreElements())
		{
			String attrname = (String) attributeNames.nextElement();
			Object attrvalue = request.getAttribute(attrname);
			print("Attribute: " + attrname + " with value: " + attrvalue);
		}
	}

	private void print( String text )
	{
		if( useLogger )
			log.log(Level.INFO, text);
		else
			stream.println(text);
	}

	public static ParameterDebugger getDebugger( PrintStream out )
	{
		return new ParameterDebugger(out, null);
	}

	public static ParameterDebugger getDebugger( Logger out )
	{
		return new ParameterDebugger(null, out);
	}
}
