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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

/**
 * Utilities for handling MIME messages from JavaMail.
 * 
 * @author Allen Petersen (akp at sourceforge dot net)
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
final class MimeUtil {

	private MimeUtil() {
	}

	/**
	 * Translates a {@link MimeMessage} into its MIME-canonical form.
	 */
	static MimeMessage canonicalize(Session session, MimeMessage mimeMessage) throws MessagingException, IOException {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		OutputStream out = new MimeCanonicalOutputStream(buffer);
		mimeMessage.writeTo(out);
		out.close();
		return new MimeMessage(session, new ByteArrayInputStream(buffer.toByteArray()));
	}

	/**
	 * Translates a {@link MimeBodyPart} into its MIME-canonical form.
	 */
	static MimeBodyPart canonicalize(MimeBodyPart mimeBodyPart) throws MessagingException, IOException {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		OutputStream out = new MimeCanonicalOutputStream(buffer);
		mimeBodyPart.writeTo(out);
		out.close();
		return new MimeBodyPart(new ByteArrayInputStream(buffer.toByteArray()));
	}

	/**
	 * A stream which filters bytes, converting all occurrences of bare
	 * {@code \n} into {@code \r\n}.
	 */
	private static class MimeCanonicalOutputStream extends java.io.FilterOutputStream {

		int lastReadByte = -1;
		byte[] crlf = new byte[] { (byte) '\r', (byte) '\n' };

		public MimeCanonicalOutputStream(java.io.OutputStream os) {
			super(os);
		}

		public void write(int b) throws java.io.IOException {
			if (b == '\r') {
				out.write(crlf);
			} else if (b == '\n') {
				if (lastReadByte != '\r')
					out.write(crlf);
			} else {
				out.write(b);
			}
			lastReadByte = b;
		}

		public void write(byte b[]) throws java.io.IOException {
			write(b, 0, b.length);
		}

		public void write(byte b[], int off, int len) throws java.io.IOException {
			int start = off;

			len = off + len;
			for (int i = start; i < len; i++) {
				if (b[i] == '\r') {
					out.write(b, start, i - start);
					out.write(crlf);
					start = i + 1;
				} else if (b[i] == '\n') {
					if (lastReadByte != '\r') {
						out.write(b, start, i - start);
						out.write(crlf);
					}
					start = i + 1;
				}
				lastReadByte = b[i];
			}
			if ((len - start) > 0)
				out.write(b, start, len - start);
		}

	}
}
