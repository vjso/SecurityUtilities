/**
 * 
 */
package org.vjso.security.util;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * @author Vijayanand Sodadasi
 *
 */
public class SecurityUtilitiesTest {

	@Test
	public void getSaltGeneratesString() {
		String generatedSalt = SecurityUtilities.getSalt();
		assertTrue (generatedSalt instanceof String);
	}

	@Test
	public void encodeEncodesPassword() {
		String rawPassword = new String("password");
		String encodedPassword = SecurityUtilities.encode(rawPassword);
		assertFalse("Encoded String shouldn't match raw String", rawPassword.equals(encodedPassword));
	}

	@Test
	public void matchesShouldMatchEncodedString() {
		String rawPassword = new String("password");
		String encodedPassword = SecurityUtilities.encode(rawPassword);
		assertTrue("Encoded String should match raw String", SecurityUtilities.matches(rawPassword, encodedPassword));
	}
}
