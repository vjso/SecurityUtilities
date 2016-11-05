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
 * @version 1.0
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
