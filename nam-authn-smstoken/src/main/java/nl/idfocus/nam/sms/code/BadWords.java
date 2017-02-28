package nl.idfocus.nam.sms.code;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.net.URL;
import java.util.LinkedList;

public class BadWords implements Serializable
{

	/**
	 * 
	 */
	private static final long serialVersionUID = 894369293980773307L;
	private final LinkedList<String> words;

	public BadWords()
	{
		this.words = loadDict();
	}

	public boolean validate(String uid) 
	{
			for ( String word : words )
			{
				if ( uid.contains( word ) )
					return false;
			}
			return true;
	}

	private LinkedList<String> loadDict()
	{
		LinkedList<String> words = new LinkedList<String>();
		// Load the internal wordlist
		URL url = BadWords.class.getResource( "BadWords.list" );
		try {
			InputStream in = url.openStream();
			BufferedReader rd = new BufferedReader( new InputStreamReader( in ) );
			String line;
			while( (line = rd.readLine() ) != null )
			{
				words.add( line.trim() );
			}
			in.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return words;
	}
}
