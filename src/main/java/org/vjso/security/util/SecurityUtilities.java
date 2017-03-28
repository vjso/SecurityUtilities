/*    
 * Security Utilities: provide utility functions to encode a string 
 * Copyright (C) <2016>  <Vijayanand Sodadasi>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.vjso.security.util;

import java.security.SecureRandom;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * 
 * Security Utility class which provides static methods to encode the password.
 * The class uses BCrypt and BCryptPasswordEncoder from Spring Security module.
 * 
 * The class uses one way encoding, that is the encoded password is never decoded.
 * The raw password which itself is encoded is compared to the stored encoded password
 * 
 * @author Vijayanand Sodadasi
 * @since 1.0
 * @version 1.1
 *
 */
public class SecurityUtilities {
	
	private static final int LOG_ROUNDS = 12;
	private static SecureRandom random = new SecureRandom();
	private static BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(LOG_ROUNDS, random); 
	
	/**
	 * Generates a random salt
	 * @return a string representing the salt
	 */
	public static String getSalt() {
		return BCrypt.gensalt(LOG_ROUNDS, random);
	}

	//Adding a comment to trigger a new build
	
	/**
	 * Generates an encoded password for the given raw password string
	 * @param password
	 * @return encoded password
	 */
	public static String encode(String password) {
		return encoder.encode(password);
	}
	
	/**
	 * 
	 * Encodes the raw password and compares it with the stored encoded password.
	 * Returns true if matches.  The encoded password is never decoded.
	 * 
	 * @param rawPassword - the raw password to encode
	 * @param encodedPassword - the encoded password from the storage
	 * @return true if the raw password, after encoding, matches the encoded password from storage
	 */
	public static boolean matches(String rawPassword, String encodedPassword) {
		return encoder.matches(rawPassword, encodedPassword);
	}
	
}
