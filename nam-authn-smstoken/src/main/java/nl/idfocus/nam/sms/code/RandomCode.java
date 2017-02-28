package nl.idfocus.nam.sms.code;

import java.io.Serializable;
import java.security.SecureRandom;

public class RandomCode implements Serializable 
{

	/**
	 * 
	 */
	private static final long serialVersionUID = 5764822800743457381L;
	private char[] chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
	private int length   = 8;
	private final String code;

	public RandomCode() 
	{
		this.code = generateCode( chars, length );
	}

	public RandomCode( char[] altChars ) 
	{
		this.chars = altChars;
		this.code  = generateCode( altChars, length );
	}

	public RandomCode( char[] altChars, int altLength ) 
	{
		this.chars  = altChars;
		this.length = altLength;
		this.code   = generateCode( altChars, altLength );
	}

	public String getCode()
	{
		return this.code;
	}

	private String generateCode( char[] chars, int length )
	{
		BadWords checker = new BadWords();
		// FIXME this needs a timeout
		while( true )
		{
			StringBuilder sb = new StringBuilder();
			SecureRandom random = new SecureRandom();
			for (int i = 0; i < length; i++) {
			    char c = chars[random.nextInt(chars.length)];
			    sb.append(c);
			}
			String output = sb.toString();
			if ( checker.validate(output) )
				return output;
		}
	}

	@Override
	public String toString()
	{
		return this.code;
	}
}
