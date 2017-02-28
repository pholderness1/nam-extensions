package nl.idfocus.nam.password;

import java.util.Comparator;

/**
 * Enables comparison between two PwdPolicy attribute values. 
 * @author mvreijn
 *
 */
public class PwdPolicyComparator implements Comparator<PwdPolicy>
{
	@Override
	public int compare(PwdPolicy left, PwdPolicy right) 
	{
		return Integer.valueOf( left.getOrder() )
				.compareTo( Integer.valueOf( right.getOrder() ) );
	}	
}

