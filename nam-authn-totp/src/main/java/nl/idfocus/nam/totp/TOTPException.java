package nl.idfocus.nam.totp;

public class TOTPException extends Exception
{
	private static final long serialVersionUID = -9046883069459915684L;

	public TOTPException( String msg ) 
	{
		super( msg );
	}

	public TOTPException(String msg, Exception e)
	{
		super(msg, e);
	}
}
