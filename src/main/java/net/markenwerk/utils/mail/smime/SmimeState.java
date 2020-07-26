/*
 * Copyright (c) 2015 Torsten Krause, Markenwerk GmbH.
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

import javax.mail.internet.MimeMultipart;
import javax.mail.internet.MimePart;

/**
 * The {@code SmimeState} of a {@link MimePart} or {@link MimeMultipart} is
 * derived from the corresponding content type and can be obtained with
 * {@link SmimeUtil#checkSignature(MimePart) checkSignature()};
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public enum SmimeState {

	/**
	 * Indicates that the {@link MimePart} or {@link MimeMultipart} is S/MIME
	 * encrypted.
	 */
	ENCRYPTED,
	
	/**
	 * Indicates that the {@link MimePart} or {@link MimeMultipart} is S/MIME
	 * signed.
	 */
	SIGNED,
	
	/**
	 * Indicates that the {@link MimePart} or {@link MimeMultipart} is S/MIME
	 * signed using the older envelope style.
	 */
	SIGNED_ENVELOPED,

	/**
	 * Indicates that the {@link MimePart} or {@link MimeMultipart} is neither
	 * S/MIME encrypted nor S/MIME signed.
	 */
	NEITHER;

}
