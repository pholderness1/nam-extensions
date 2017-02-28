package nl.idfocus.nam.sms;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

import nl.idfocus.nam.sms.SmsParameterDesc.SmsParameterType;
import nl.idfocus.nam.util.LogFormatter;

public class SMSCity implements SmsProvider 
{
	private static final Logger logger  = LogFormatter.getConsoleLogger( SMSCity.class.getName() );
	private static final Level loglevel = Level.INFO;
	private static final Level dbglevel = Level.FINE;
	private static final Level errlevel = Level.SEVERE;

	public static final String PARAM_USR = "username";
	public static final String PARAM_PWD = "password";
	public static final String PARAM_SND = "sender";

	private final String postUrl;
	private final String responseType;
	private String username;
	private String password;
	private String sender;
	private boolean initialized;
	private String responseCode;
	private String responseMessage;
	private String creditBalance;

	public SMSCity() 
	{
		this.postUrl = "http://api.smscity.com/gateway/sms.php";
		this.responseType = "XML";
	}

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
		// TODO check mandatory stuff
		this.username = config.getStringValue( PARAM_USR );
		this.password = config.getStringValue( PARAM_PWD );
		this.sender   = config.getPasswordValue( PARAM_SND );
		this.initialized = true;
	}

	@Override
	public boolean send( String message, String number, int timeout ) 
	{
		logger.log( dbglevel, "Sending "+message+" to "+number );
		StringBuffer postData = new StringBuffer();

		// Create default request parameters
		try {
			postData.append("username=" + URLEncoder.encode(this.username, "UTF-8"));
			postData.append("&password=" + URLEncoder.encode(this.password, "UTF-8"));
			postData.append("&sender=" + URLEncoder.encode(this.sender, "UTF-8"));
			postData.append("&responsetype=" + URLEncoder.encode(this.responseType, "UTF-8"));
			// Add message body
			postData.append("&body=" + URLEncoder.encode(message, "UTF-8"));
			// Add destination number
			postData.append("&destination=" + URLEncoder.encode(number, "UTF-8") );
			// Set the code as the message reference
			postData.append("&reference=" + URLEncoder.encode(message, "UTF-8") );
		} catch (UnsupportedEncodingException e) {
			logger.log( errlevel, "Exception: "+e.getMessage() );
			return false;
		}

		try {
			URL url = new URL( this.postUrl );
			URLConnection conn = url.openConnection();
			if ( timeout > 0 )
				conn.setReadTimeout( timeout );
			conn.setDoOutput(true);
			OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
			wr.write(postData.toString());
			wr.flush();

			// Get the response
			BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));

			try {
				XMLInputFactory inputFactory = XMLInputFactory.newInstance();
				XMLEventReader reader = inputFactory.createXMLEventReader(rd);
				while (reader.hasNext()) {
					XMLEvent event = reader.nextEvent();
					if (event.isStartElement()) {
						StartElement element = (StartElement) event;
						if (element.getName().toString().equals("responseCode")) {
							event = reader.nextEvent();
							this.responseCode = event.asCharacters().getData();
							continue;
						} else if (element.getName().toString().equals("responseMessage")) {
							event = reader.nextEvent();
							this.responseMessage = event.asCharacters().getData();
							continue;
						} else if (element.getName().toString().equals("credits")) {
							event = reader.nextEvent();
							this.creditBalance = event.asCharacters().getData();
							continue;
						}
					}
				}
			} catch (Exception e) {
				logger.log( errlevel, "Exception reading response: "+e.getMessage() );				
			}
			logger.log( dbglevel, "Response message: "+responseMessage );
			logger.log( loglevel, "New credit balance: "+creditBalance );
			wr.close();
			rd.close();
		} catch (Exception e) {}
		if ( this.responseCode == "01" )
		{
			logger.log( loglevel, "message sent successfully!" );
			return true;
		}
		logger.log( loglevel, "message NOT sent!" );
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
		return "SMSCity Provider";
	}

	@Override
	public SmsParameterDesc[] getParameters() 
	{
		SmsParameterDesc param1 = new SmsParameterDesc( PARAM_USR, SmsParameterType.STRING );
		SmsParameterDesc param2 = new SmsParameterDesc( PARAM_PWD, SmsParameterType.STRING );
		SmsParameterDesc param3 = new SmsParameterDesc( PARAM_SND, SmsParameterType.STRING );
		return new SmsParameterDesc[]{ param1, param2, param3, }; 
	}

	@Override
	public boolean needPrincipal() 
	{
		return false;
	}

	@Override
	public void update(SmsConfig config) {	}

}
