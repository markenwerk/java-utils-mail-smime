/*
 * Copyright (C) 2015 Torsten Krause.
 * 
 * This file is part of 'A S/MIME library for JavaMail', hereafter
 * called 'this library', identified by the following coordinates:
 * 
 *    groupID: net.markenwerk
 *    artifactId: utils-mail-smime
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

import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;

/**
 * A wrapper around a {@link PrivateKey} and a chain of {@link X509Certificate
 * X509Certificates} used to sign or decrypt a MIME message.
 * 
 * @author Allen Petersen (akp at sourceforge dot net)
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public class SmimeKey {

	private final PrivateKey privateKey;
	private final X509Certificate[] certificateChain;
	private List<String> addresses;

	/**
	 * Create a new {@code SmimeKey} with the given private key and certificate
	 * chain.
	 * 
	 * @param privateKey
	 *            The {@link PrivateKey} of this {@code SmimeKey}
	 * @param certificateChain
	 *            The chain of {@link X509Certificate X509Certificates} of this
	 *            {@code SmimeKey} starting with the certificate that holds the
	 *            public key that corresponds to the given private key and
	 *            ending with the trust anchor.
	 */
	public SmimeKey(PrivateKey privateKey, X509Certificate... certificateChain) {
		this.privateKey = privateKey;
		this.certificateChain = certificateChain;
	}

	/**
	 * Returns the private key of this {@code SmimeKey}.
	 * 
	 * @return The {@link PrivateKey}.
	 */
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	/**
	 * Returns the certificate that holds the public key that corresponds to the
	 * private key of this {@code SmimeKey}.
	 * 
	 * @return The {@link X509Certificate}.
	 */
	public X509Certificate getCertificate() {
		return certificateChain[0];
	}

	/**
	 * Returns the chain of certificates of this {@code SmimeKey} starting with
	 * the certificate that holds the public key that corresponds to the private
	 * key of this {@code SmimeKey} and ending with the trust anchor.
	 * 
	 * @return The chain of {@link X509Certificate X509Certificates}.
	 */
	public X509Certificate[] getCertificateChain() {
		return certificateChain;
	}

	/**
	 * Compiles and returns the list of email address associated with the
	 * {@link #getCertificate() certificate} of this {@code SmimeKey} by
	 * inspecting the subjects distinguished name.
	 * 
	 * @return A {@link Collections#unmodifiableList(List) unmodifiable list} of
	 *         email addresses.
	 */
	public List<String> getAssociatedAddresses() {
		if (addresses == null) {
			extractAssociatedAddresses();
		}
		return addresses;
	}

	private void extractAssociatedAddresses() {
		List<String> addresses = new ArrayList<String>();
		try {
			X509Certificate certificate = getCertificate();
			if (null != certificate) {
				Principal principal = certificate.getSubjectDN();
				if (null != principal) {
					String name = principal.getName();
					StringTokenizer tokenizer = new StringTokenizer(name, ",");
					while (tokenizer.hasMoreTokens()) {
						String next = tokenizer.nextToken();
						if (next.startsWith("E="))
							addresses.add(next.substring(2));
					}
				}
			}
		} catch (Exception e) {
		}
		this.addresses = Collections.unmodifiableList(addresses);
	}

}
