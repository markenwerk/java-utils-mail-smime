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

/**
 * A {@link RuntimeException} that is used to indicate S/MIME specific
 * missbehaviors or to wrap other {@link Exception Exceptions} that were thrown
 * during the processing of S/MIME specific operations.
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public class SmimeException extends RuntimeException {

	private static final long serialVersionUID = 5400625787171945502L;

	/**
	 * Create a new {@code SmimeException} with the given message and cause.
	 * 
	 * @param message
	 *            The message of this {@code SmimeException}.
	 * @param cause
	 *            The causing {@link Exception} wrapped by this
	 *            {@code SmimeException}.
	 */
	public SmimeException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Create a new {@code SmimeException} with the given message.
	 * 
	 * @param message
	 *            The message of this {@code SmimeException}.
	 */
	public SmimeException(String message) {
		super(message);
	}

	/**
	 * Create a new {@code SmimeException} with the given cause.
	 * 
	 * @param cause
	 *            The causing {@link Exception} wrapped by this
	 *            {@code SmimeException}.
	 */
	public SmimeException(Throwable cause) {
		super(cause);
	}

}
