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

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

/**
 * A {@link MimeBodyPart} that exposes the method {@code updateHeaders()} with
 * {@code public} visibility.
 * 
 * @author Allen Petersen (akp at sourceforge dot net)
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
class UpdatableMimeBodyPart extends MimeBodyPart {

	/**
	 * Create a new {@code UpdatableMimeBodyPart}.
	 */
	public UpdatableMimeBodyPart() {
		super();
	}

	/**
	 * Create a new {@code UpdatableMimeBodyPart} by reading and parsing the
	 * data from the specified input stream.
	 * 
	 * @param in
	 *            The {@link InputStream} to be read.
	 * @throws MessagingException
	 *             If the {@code MimeBodyPart} couldn't be read.
	 */
	public UpdatableMimeBodyPart(InputStream in) throws MessagingException {
		super(in);
	}

	/**
	 * Calls updateHeaders().
	 */
	public void updateHeaders() throws MessagingException {
		super.updateHeaders();
	}

}
