/*
 * A S/MIME library for JavaMail
 * (groupID: net.markenwerk, artifactId: utils-mail-smime)
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 * 
 * See the LICENSE and NOTICE files in the root directory for further
 * information.
 */
package net.markenwerk.utils.mail.smime;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * A wrapper around a {@link KeyStore} that can be initialized with a PKCS12
 * keystore and is used to obtain {@link SmimeKey SmimeKeys}.
 * 
 * @author Allen Petersen (akp at sourceforge dot net)
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public class SmimeKeyStore {

	private KeyStore keyStore = null;

	/**
	 * Creates a new {@code SmimeKeyStore} by loading a PKCS12 keystore from a
	 * the given input stream.
	 * 
	 * <p>
	 * The character array holding the password is overwritten with {@code 0s}
	 * after it has been used.
	 * 
	 * @param stream
	 *            The {@link InputStream} to read the PKCS12 keystore from.
	 * @param password
	 *            The password to unlock the PKCS12 keystore with.
	 */
	public SmimeKeyStore(InputStream stream, char[] password) {
		this(stream, password, true);
	}

	/**
	 * Creates a new {@code SmimeKeyStore} by loading a PKCS12 keystore from a
	 * the given input stream.
	 * 
	 * <p>
	 * If {@code discardPassword} is set to {@code true}, the character array
	 * holding the password is overwritten with {@code 0s} after it has been
	 * used.
	 * 
	 * @param stream
	 *            The {@link InputStream} to read the PKCS12 keystore from.
	 * @param password
	 *            The password to unlock the PKCS12 keystore with.
	 * @param discardPassword
	 *            Whether to overwrite the {@code char[]} holding the password
	 *            after it has been used.
	 */
	public SmimeKeyStore(InputStream stream, char[] password, boolean discardPassword) {
		try {
			keyStore = KeyStore.getInstance("PKCS12", "BC");
			keyStore.load(stream, password);
		} catch (Exception e) {
			throw new SmimeException("Couldn't initialize SmimeKeyStore", e);
		} finally {
			if (discardPassword) {
				overwrite(password);
			}
		}
	}

	private void overwrite(char[] password) {
		if (null != password) {
			for (int i = 0, n = password.length; i < n; i++) {
				password[i] = 0;
			}
		}
	}

	/**
	 * Returns the number of entries in the underlying PKCS12 keystore.
	 *
	 * @return The number of entries in the underlying {@link KeyStore}.
	 *
	 */
	public int size() {
		try {
			return keyStore.size();
		} catch (KeyStoreException e) {
			throw new SmimeException("Couldn't retrieve the number of entries from SmimeKeyStore", e);
		}
	}

	/**
	 * Returns the S/MIME key associated with the given alias, using the given
	 * password to recover it.
	 * 
	 * <p>
	 * The character array holding the password is overwritten with {@code 0s}
	 * after it has been used.
	 * 
	 * @param alias
	 *            The alias.
	 * @param password
	 *            The password to unlock the {@link PrivateKey} keystore with.
	 *
	 * @return The requested {@link SmimeKey}, or null if the given alias does
	 *         not exist or does not identify a private key entry.
	 */
	public SmimeKey getPrivateKey(String alias, char[] password) {
		return getPrivateKey(alias, password, true);
	}

	/**
	 * Returns the S/MIME key associated with the given alias, using the given
	 * password to recover it.
	 * 
	 * <p>
	 * If {@code discardPassword} is set to {@code true}, the character array
	 * holding the password is overwritten with {@code 0s} after it has been
	 * used.
	 * 
	 * @param alias
	 *            The alias.
	 * @param password
	 *            The password to unlock the {@link PrivateKey} keystore with.
	 * @param discardPassword
	 *            Whether to overwrite the {@code char[]} holding the password
	 *            after it has been used.
	 *
	 * @return The requested {@link SmimeKey}, or null if the given alias does
	 *         not exist or does not identify a private key entry.
	 */
	public SmimeKey getPrivateKey(String alias, char[] password, boolean discardPassword) {
		try {
			if (containsPrivateKeyAlias(alias)) {
				PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
				Certificate[] certificateChain = keyStore.getCertificateChain(alias);
				return new SmimeKey(privateKey, copy(certificateChain));
			}
			return null;
		} catch (Exception e) {
			throw new SmimeException("Couldn't recover SmimeKey from SmimeKeyStore", e);
		} finally {
			if (discardPassword) {
				overwrite(password);
			}
		}
	}

	private X509Certificate[] copy(Certificate[] certificateChain) {
		X509Certificate[] x509certificateChain = new X509Certificate[certificateChain.length];
		for (int i = 0, n = certificateChain.length; i < n; i++) {
			x509certificateChain[i] = (X509Certificate) certificateChain[i];
		}
		return x509certificateChain;
	}

	/**
	 * Returns a set containing all aliases listed in the PKCS12 keystore.
	 *
	 * @return A {@link Collections#unmodifiableSet(Set) unmodifiable set} of
	 *         aliases.
	 */
	public Set<String> getPrivateKeyAliases() {
		try {
			Enumeration<String> aliases = keyStore.aliases();
			Set<String> aliasSet = new HashSet<String>();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				if (keyStore.isKeyEntry(alias))
					aliasSet.add(alias);
			}
			return Collections.unmodifiableSet(aliasSet);
		} catch (Exception e) {
			throw new SmimeException("Couldn't recover aliases from SmimeKeyStore", e);
		}
	}

	/**
	 * Checks if the given alias exists in the PKCS12 keystore.
	 *
	 * @param alias
	 *            The alias to look for.
	 *
	 * @return {@code true} if the alias exists, {@code false} otherwise.
	 */
	public boolean containsPrivateKeyAlias(String alias) {
		try {
			return keyStore.isKeyEntry(alias);
		} catch (Exception e) {
			throw new SmimeException("Couldn't recover aliases from SmimeKeyStore", e);
		}
	}

}
