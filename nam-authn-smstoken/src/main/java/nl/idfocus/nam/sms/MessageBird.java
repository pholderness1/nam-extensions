/* 
 * $Id: MessageBird.java 66 2016-02-08 22:13:18Z mvreijn $
 */


package nl.idfocus.nam.sms;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import nl.idfocus.nam.sms.SmsParameterDesc.SmsParameterType;
import nl.idfocus.nam.util.LogFormatter;

public class MessageBird implements SmsProvider
{
	private static final Logger logger  = LogFormatter.getConsoleLogger( MessageBird.class.getName() );
	private static final Level loglevel = Level.INFO;
	private static final Level dbglevel = Level.FINE;
	private static final Level errlevel = Level.SEVERE;

	public static final String PARAM_URL = "url";
	public static final String PARAM_USR = "userName";
	public static final String PARAM_PWD = "password";
	public static final String PARAM_APP = "sender";
	public static final String PARAM_DEV = "development";
	public static final String PARAM_REF = "reference";

	private String url;
	private String userName;
	private String password;
	private String sender;
	private String reference;
	private String responseType;
	
	private boolean development = false;
	private boolean initialized = false;

	@Override
	public void init( SmsConfig config, boolean dbg ) 
	{
		logger.log( loglevel, "Initializing "+getName() );
		if ( dbg )
		{
			logger.setLevel(dbglevel);
			for ( Handler hd : logger.getHandlers() )
				hd.setLevel(dbglevel);
		}
		if ( config.getStringValue( PARAM_URL ) == null )
			url			= "https://api.messagebird.com/api/sms";
		else
			url			= config.getStringValue( PARAM_URL );
		responseType	= "SIMPLE";
		userName		= config.getStringValue( PARAM_USR );
		password		= config.getStringValue( PARAM_PWD );
		sender			= config.getStringValue( PARAM_APP );
		development		= Boolean.parseBoolean(config.getStringValue( PARAM_DEV ));
		reference		= config.getStringValue( PARAM_REF );
		initialized		= true;
		logger.log( loglevel, "Done." );
	}
	
	@Override
	public boolean send( String message, String number, int timeout ) 
	{
		StringBuffer postData = new StringBuffer();

		try {
			postData.append( "username"  + "=" + URLEncoder.encode( userName, "UTF-8" ) );
			postData.append( "&" );
			postData.append( "password"  + "=" + URLEncoder.encode( password, "UTF-8" ) );
			postData.append( "&" );
			postData.append( "destination"  + "=" + URLEncoder.encode( number, "UTF-8" ) );
			postData.append( "&" );
			postData.append( "body"  + "=" + URLEncoder.encode( message, "UTF-8" ) );
			postData.append( "&" );
			postData.append( "sender"  + "=" + URLEncoder.encode( sender, "UTF-8" ) );
			if (reference != null ){
				postData.append( "&" );
				postData.append( "reference"  + "=" + URLEncoder.encode( reference, "UTF-8" ) );
			}	
			postData.append( "&" );
			postData.append( "responsetype"  + "=" + URLEncoder.encode( responseType, "UTF-8" ) );
			if (development){
				postData.append( "&" );
				postData.append( "test=1" );
			}
			logger.log( dbglevel, String.format( "Assembled POST data %s.", postData ) ); 
		}
		catch (UnsupportedEncodingException e)
		{
			return false;
		}

		try {
			URL url = new URL( this.url );
			HttpURLConnection conn = (HttpURLConnection)url.openConnection();

			logger.log( dbglevel, String.format( "Connecting to %s for sending message.", conn.toString() ) );
			if ( timeout > 0 )
				conn.setReadTimeout( timeout );
			conn.setDoOutput(true);
			OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
			wr.write(postData.toString());
			wr.flush();

			// Get the response
			int response = conn.getResponseCode();
			conn.disconnect();

			if ( response == HttpURLConnection.HTTP_OK )
				return true;
			else
				logger.log( errlevel, String.format( "Received response code %s from Messagebird service.", response ) ); 
		}
		catch (IOException e)
		{
			logger.log( errlevel, String.format( "Encountered \'%s\' while contacting Messagebird service.", e.getMessage() ) ); 
		}
		return false;
	}

	@Override
	public boolean ready() 
	{
		if ( this.initialized )
			return true;
		return false;
	}

	@Override
	public String getName() 
	{
		return "MessageBird Provider";
	}

	@Override
	public SmsParameterDesc[] getParameters() 
	{
		SmsParameterDesc param1 = new SmsParameterDesc( PARAM_USR, SmsParameterType.STRING );
		SmsParameterDesc param2 = new SmsParameterDesc( PARAM_PWD, SmsParameterType.STRING );
		SmsParameterDesc param3 = new SmsParameterDesc( PARAM_APP, SmsParameterType.STRING );
	//		SmsParameterDesc param4 = new SmsParameterDesc( PARAM_DEV, SmsParameterType.STRING );
	//		SmsParameterDesc param5 = new SmsParameterDesc( PARAM_REF, SmsParameterType.STRING );
		return new SmsParameterDesc[]{ param1, param2, param3, }; //param4, param5 };
	}

	@Override
	public boolean needPrincipal() 
	{
		return false;
	}

	@Override
	public void update(SmsConfig config) 
	{
	}


}
