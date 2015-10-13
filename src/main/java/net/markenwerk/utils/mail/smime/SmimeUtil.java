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

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.Header;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.ContentType;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.internet.MimePart;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.Store;

/**
 * Utilities for handling S/MIME specific operations on MIME messages from
 * JavaMail.
 * 
 * @author Allen Petersen (akp at sourceforge dot net)
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public final class SmimeUtil {

	static {
		if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
			Security.addProvider(new BouncyCastleProvider());
			updateMailcapCommandMap();
		}
	}

	private SmimeUtil() {
	}

	private static void updateMailcapCommandMap() {
		MailcapCommandMap map = (MailcapCommandMap) CommandMap.getDefaultCommandMap();
		map.addMailcap("application/pkcs7-signature;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
		map.addMailcap("application/pkcs7-mime;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
		map.addMailcap("application/x-pkcs7-signature;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
		map.addMailcap("application/x-pkcs7-mime;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
		map.addMailcap("multipart/signed;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");
		CommandMap.setDefaultCommandMap(map);
	}

	/**
	 * Encrypts a MIME message and yields a new S/MIME encrypted MIME message.
	 * 
	 * @param session
	 *            The {@link Session} that is used in conjunction with the
	 *            original {@link MimeMessage}.
	 * @param mimeMessage
	 *            The original {@link MimeMessage} to be encrypted.
	 * @param certificate
	 *            The {@link X509Certificate} used to obtain the
	 *            {@link PublicKey} to encrypt the original message with.
	 * @return The new S/MIME encrypted {@link MimeMessage}.
	 */
	public static MimeMessage encrypt(Session session, MimeMessage mimeMessage, X509Certificate certificate) {
		try {
			MimeMessage encryptedMimeMessage = new MimeMessage(session);
			copyHeaders(mimeMessage, encryptedMimeMessage);

			SMIMEEnvelopedGenerator generator = prepareGenerator(certificate);
			OutputEncryptor encryptor = prepareEncryptor();

			MimeBodyPart encryptedMimeBodyPart = generator.generate(mimeMessage, encryptor);
			copyContent(encryptedMimeBodyPart, encryptedMimeMessage);
			copyHeaders(encryptedMimeBodyPart, encryptedMimeMessage);
			encryptedMimeMessage.saveChanges();
			return encryptedMimeMessage;
		} catch (Exception e) {
			throw handledException(e);
		}
	}

	/**
	 * Encrypts a MIME body part and yields a new S/MIME encrypted MIME body
	 * part.
	 * 
	 * @param mimeBodyPart
	 *            The original {@link MimeBodyPart} to be encrypted.
	 * @param certificate
	 *            The {@link X509Certificate} used to obtain the
	 *            {@link PublicKey} to encrypt the original body part with.
	 * @return The new S/MIME encrypted {@link MimeBodyPart}.
	 */
	public static MimeBodyPart encrypt(MimeBodyPart mimeBodyPart, X509Certificate certificate) {
		try {
			SMIMEEnvelopedGenerator generator = prepareGenerator(certificate);
			OutputEncryptor encryptor = prepareEncryptor();

			MimeBodyPart encryptedMimeBodyPart = generator.generate(mimeBodyPart, encryptor);
			return encryptedMimeBodyPart;

		} catch (Exception e) {
			throw handledException(e);
		}
	}

	private static void copyHeaders(MimeBodyPart fromBodyPart, MimeMessage toMessage) throws MessagingException {
		@SuppressWarnings("unchecked")
		Enumeration<Header> headers = fromBodyPart.getAllHeaders();
		copyHeaders(headers, toMessage);
	}

	private static void copyHeaders(MimeMessage fromMessage, MimeMessage toMessage) throws MessagingException {
		@SuppressWarnings("unchecked")
		Enumeration<Header> headers = fromMessage.getAllHeaders();
		copyHeaders(headers, toMessage);
	}

	private static void copyHeaders(Enumeration<Header> headers, MimeMessage toMessage) throws MessagingException {
		while (headers.hasMoreElements()) {
			Header header = headers.nextElement();
			toMessage.setHeader(header.getName(), header.getValue());
		}
	}

	private static SMIMEEnvelopedGenerator prepareGenerator(X509Certificate certificate)
			throws CertificateEncodingException {
		JceKeyTransRecipientInfoGenerator infoGenerator = new JceKeyTransRecipientInfoGenerator(certificate);
		infoGenerator.setProvider(BouncyCastleProvider.PROVIDER_NAME);
		SMIMEEnvelopedGenerator generator = new SMIMEEnvelopedGenerator();
		generator.addRecipientInfoGenerator(infoGenerator);
		return generator;
	}

	private static OutputEncryptor prepareEncryptor() throws CMSException {
		return new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(
				BouncyCastleProvider.PROVIDER_NAME).build();
	}

	/**
	 * Decrypts a S/MIME encrypted MIME message and yields a new MIME message.
	 * 
	 * @param session
	 *            The {@link Session} that is used in conjunction with the
	 *            encrypted {@link MimeMessage}.
	 * @param mimeMessage
	 *            The encrypted {@link MimeMessage} to be decrypted.
	 * @param smimeKey
	 *            The {@link SmimeKey} used to obtain the {@link PrivateKey} to
	 *            decrypt the encrypted message with.
	 * @return The new S/MIME decrypted {@link MimeMessage}.
	 */
	public static MimeMessage decrypt(Session session, MimeMessage mimeMessage, SmimeKey smimeKey) {
		try {
			byte[] content = decryptContent(new SMIMEEnveloped(mimeMessage), smimeKey);
			MimeBodyPart mimeBodyPart = SMIMEUtil.toMimeBodyPart(content);

			MimeMessage decryptedMessage = new MimeMessage(session);
			copyHeaderLines(mimeMessage, decryptedMessage);
			copyContent(mimeBodyPart, decryptedMessage);
			decryptedMessage.setHeader("Content-Type", mimeBodyPart.getContentType());
			return decryptedMessage;

		} catch (Exception e) {
			throw handledException(e);
		}
	}

	/**
	 * Decrypts a S/MIME encrypted MIME body part and yields a new MIME body
	 * part.
	 * 
	 * @param mimeBodyPart
	 *            The encrypted {@link MimeBodyPart} to be decrypted.
	 * @param smimeKey
	 *            The {@link SmimeKey} used to obtain the {@link PrivateKey} to
	 *            decrypt the encrypted body part with.
	 * @return The new S/MIME decrypted {@link MimeBodyPart}.
	 */
	public static MimeBodyPart decrypt(MimeBodyPart mimeBodyPart, SmimeKey smimeKey) {
		try {
			return SMIMEUtil.toMimeBodyPart(decryptContent(new SMIMEEnveloped(mimeBodyPart), smimeKey));
		} catch (Exception e) {
			throw handledException(e);
		}

	}

	/**
	 * Decrypts a S/MIME encrypted MIME multipart and yields a new MIME body
	 * part.
	 * 
	 * @param mimeMultipart
	 *            The encrypted {@link MimeMultipart} to be decrypted.
	 * @param smimeKey
	 *            The {@link SmimeKey} used to obtain the {@link PrivateKey} to
	 *            decrypt the encrypted multipart with.
	 * @return The new S/MIME decrypted {@link MimeBodyPart}.
	 */
	public static MimeBodyPart decrypt(MimeMultipart mimeMultipart, SmimeKey smimeKey) {
		try {
			MimeBodyPart mimeBodyPart = new MimeBodyPart();
			mimeBodyPart.setContent(mimeMultipart);
			mimeBodyPart.setHeader("Content-Type", mimeMultipart.getContentType());
			return decrypt(mimeBodyPart, smimeKey);
		} catch (Exception e) {
			throw handledException(e);
		}
	}

	private static byte[] decryptContent(SMIMEEnveloped smimeEnveloped, SmimeKey smimeKey) throws MessagingException,
			CMSException {
		X509Certificate certificate = smimeKey.getCertificate();
		PrivateKey privateKey = smimeKey.getPrivateKey();

		RecipientInformationStore recipients = smimeEnveloped.getRecipientInfos();
		RecipientInformation recipient = recipients.get(new JceKeyTransRecipientId(certificate));

		if (null == recipient) {
			throw new MessagingException("no recipient");
		}

		JceKeyTransRecipient transportRecipient = new JceKeyTransEnvelopedRecipient(privateKey);
		transportRecipient.setProvider(BouncyCastleProvider.PROVIDER_NAME);
		return recipient.getContent(transportRecipient);
	}

	private static void copyHeaderLines(MimeMessage fromMessage, MimeMessage toMessage) throws MessagingException {
		@SuppressWarnings("unchecked")
		Enumeration<String> headerLines = fromMessage.getAllHeaderLines();
		while (headerLines.hasMoreElements()) {
			String nextElement = headerLines.nextElement();
			toMessage.addHeaderLine(nextElement);
		}
	}

	private static void copyContent(MimeBodyPart fromBodyPart, MimeMessage toMessage) throws MessagingException,
			IOException {
		toMessage.setContent(fromBodyPart.getContent(), fromBodyPart.getContentType());
	}

	/**
	 * Signs a MIME body part and yields a new S/MIME signed MIME body part.
	 * 
	 * @param mimeBodyPart
	 *            The original {@link MimeBodyPart} to be signed.
	 * @param smimeKey
	 *            The {@link SmimeKey} used to obtain the {@link PrivateKey} to
	 *            sign the original body part with.
	 * @return The new S/MIME signed {@link MimeBodyPart}.
	 */
	public static MimeBodyPart sign(MimeBodyPart mimeBodyPart, SmimeKey smimeKey) {
		try {
			SMIMESignedGenerator generator = getGenerator(smimeKey);
			MimeMultipart signedMimeMultipart = generator.generate(MimeUtil.canonicalize(mimeBodyPart));
			MimeBodyPart signedMimeBodyPart = new MimeBodyPart();
			signedMimeBodyPart.setContent(signedMimeMultipart);
			return signedMimeBodyPart;

		} catch (Exception e) {
			throw handledException(e);
		}

	}

	private static SMIMESignedGenerator getGenerator(SmimeKey smimeKey) throws CertificateEncodingException,
			OperatorCreationException {
		SMIMESignedGenerator generator = new SMIMESignedGenerator();
		generator.addCertificates(getCertificateStore(smimeKey));
		generator.addSignerInfoGenerator(getInfoGenerator(smimeKey));
		return generator;
	}

	private static SignerInfoGenerator getInfoGenerator(SmimeKey smimeKey) throws OperatorCreationException,
			CertificateEncodingException {
		JcaSimpleSignerInfoGeneratorBuilder builder = new JcaSimpleSignerInfoGeneratorBuilder();
		builder.setSignedAttributeGenerator(new AttributeTable(getSignedAttributes(smimeKey)));
		builder.setProvider(BouncyCastleProvider.PROVIDER_NAME);

		PrivateKey privateKey = smimeKey.getPrivateKey();
		X509Certificate certificate = smimeKey.getCertificate();
		SignerInfoGenerator infoGenerator = builder.build("SHA256withRSA", privateKey, certificate);
		return infoGenerator;
	}

	private static ASN1EncodableVector getSignedAttributes(SmimeKey smimeKey) {
		ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
		IssuerAndSerialNumber issuerAndSerialNumber = getIssuerAndSerialNumber(smimeKey);
		signedAttributes.add(new SMIMEEncryptionKeyPreferenceAttribute(issuerAndSerialNumber));
		signedAttributes.add(new SMIMECapabilitiesAttribute(getCapabilityVector()));
		return signedAttributes;
	}

	private static SMIMECapabilityVector getCapabilityVector() {
		SMIMECapabilityVector capabilityVector = new SMIMECapabilityVector();
		capabilityVector.addCapability(SMIMECapability.dES_EDE3_CBC);
		capabilityVector.addCapability(SMIMECapability.rC2_CBC, 128);
		capabilityVector.addCapability(SMIMECapability.dES_CBC);
		return capabilityVector;
	}

	private static IssuerAndSerialNumber getIssuerAndSerialNumber(SmimeKey smimeKey) {
		X509Certificate certificate = smimeKey.getCertificate();
		BigInteger serialNumber = certificate.getSerialNumber();
		X500Name issuerName = new X500Name(certificate.getIssuerDN().getName());
		IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(issuerName, serialNumber);
		return issuerAndSerialNumber;
	}

	private static JcaCertStore getCertificateStore(SmimeKey smimeKey) throws CertificateEncodingException {
		Certificate[] certificateChain = smimeKey.getCertificateChain();
		X509Certificate certificate = smimeKey.getCertificate();

		List<Certificate> certificateList = null;
		if (certificateChain != null && certificateChain.length > 0) {
			certificateList = Arrays.asList(certificateChain);
		} else {
			certificateList = new ArrayList<Certificate>();
			certificateList.add(certificate);
		}
		return new JcaCertStore(certificateList);
	}

	/**
	 * Signs a MIME message and yields a new S/MIME signed MIME message.
	 * 
	 * @param session
	 *            The {@link Session} that is used in conjunction with the
	 *            original {@link MimeMessage}.
	 * @param mimeMessage
	 *            The original {@link MimeMessage} to be signed.
	 * @param smimeKey
	 *            The {@link SmimeKey} used to obtain the {@link PrivateKey} to
	 *            sign the original message with.
	 * @return The new S/MIME signed {@link MimeMessage}.
	 */
	public static MimeMessage sign(Session session, MimeMessage mimeMessage, SmimeKey smimeKey) {
		try {
			MimeMessage signedMessage = new MimeMessage(session);
			copyHeaderLines(mimeMessage, signedMessage);
			copyContent(sign(extractMimeBodyPart(mimeMessage), smimeKey), signedMessage);
			return signedMessage;
		} catch (Exception e) {
			throw handledException(e);
		}
	}

	private static MimeBodyPart extractMimeBodyPart(MimeMessage mimeMessage) throws IOException, MessagingException {
		Object content = mimeMessage.getContent();
		UpdatableMimeBodyPart updateableMimeBodyPart = new UpdatableMimeBodyPart();
		if (content instanceof Multipart) {
			updateableMimeBodyPart.setContent((Multipart) content);
		} else {
			updateableMimeBodyPart.setContent(content, mimeMessage.getDataHandler().getContentType());
		}
		updateableMimeBodyPart.updateHeaders();
		return updateableMimeBodyPart;
	}

	/**
	 * Checks the signature on a S/MIME signed MIME multipart.
	 * 
	 * @param mimeMultipart
	 *            The {@link MimeMultipart} to be checked.
	 * @return {@code true} if the multipart is correctly signed, {@code false}
	 *         otherwise.
	 */
	public static boolean checkSignature(MimeMultipart mimeMultipart) {
		try {
			return checkSignature(new SMIMESigned(mimeMultipart));
		} catch (Exception e) {
			throw handledException(e);
		}
	}

	/**
	 * Checks the signature on a S/MIME signed MIME part (i.e. MIME message).
	 * 
	 * @param mimePart
	 *            The {@link MimePart} to be checked.
	 * @return {@code true} if the part is correctly signed, {@code false}
	 *         otherwise.
	 */
	public static boolean checkSignature(MimePart mimePart) {
		try {
			if (mimePart.isMimeType("multipart/signed")) {
				return checkSignature(new SMIMESigned((MimeMultipart) mimePart.getContent()));
			} else if (mimePart.isMimeType("application/pkcs7-mime") || mimePart.isMimeType("application/x-pkcs7-mime")) {
				return checkSignature(new SMIMESigned(mimePart));
			} else {
				throw new SmimeException("Message not signed");
			}
		} catch (Exception e) {
			throw handledException(e);
		}
	}

	/**
	 * Checks a SMIMESigned to make sure that the signature matches.
	 */
	private static boolean checkSignature(SMIMESigned smimeSigned) throws MessagingException, IOException,
			GeneralSecurityException {
		try {
			boolean returnValue = true;

			@SuppressWarnings("rawtypes")
			Store certificates = smimeSigned.getCertificates();
			Iterator<SignerInformation> signerInformations = smimeSigned.getSignerInfos().getSigners().iterator();

			while (returnValue && signerInformations.hasNext()) {
				SignerInformation signerInformation = signerInformations.next();
				X509Certificate certificate = getCertificate(certificates, signerInformation.getSID());
				SignerInformationVerifier verifier = getVerifier(certificate);
				if (!signerInformation.verify(verifier)) {
					returnValue = false;
				}
			}
			return returnValue;

		} catch (Exception e) {
			throw handledException(e);
		}
	}

	private static X509Certificate getCertificate(@SuppressWarnings("rawtypes") Store certificates, SignerId signerId)
			throws CertificateException {
		@SuppressWarnings({ "unchecked" })
		X509CertificateHolder certificateHolder = (X509CertificateHolder) certificates.getMatches(signerId).iterator()
				.next();
		JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
		certificateConverter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
		return certificateConverter.getCertificate(certificateHolder);
	}

	private static SignerInformationVerifier getVerifier(X509Certificate certificate) throws OperatorCreationException {
		JcaSimpleSignerInfoVerifierBuilder builder = new JcaSimpleSignerInfoVerifierBuilder();
		builder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
		return builder.build(certificate);
	}

	/**
	 * Returns the signed MIME body part of a S/MIME signed MIME multipart.
	 * 
	 * @param mimeMultipart
	 *            The {@link MimeMultipart} to be stripped off.
	 * @return The signed {@link MimeBodyPart} contained in the
	 *         {@link MimeMultipart}.
	 */
	public static MimeBodyPart getSignedContent(MimeMultipart mimeMultipart) {
		try {
			return new SMIMESigned(mimeMultipart).getContent();
		} catch (Exception e) {
			throw handledException(e);
		}
	}

	/**
	 * Returns the signed MIME body part of a S/MIME signed MIME part (i.e. MIME
	 * message).
	 * 
	 * @param mimePart
	 *            The {@link MimePart} to be stripped off.
	 * @return The signed {@link MimeBodyPart} contained in the {@link MimePart}
	 *         .
	 */
	public static MimeBodyPart getSignedContent(MimePart mimePart) {
		try {
			if (mimePart.isMimeType("multipart/signed")) {
				return new SMIMESigned((MimeMultipart) mimePart.getContent()).getContent();
			} else if (mimePart.isMimeType("application/pkcs7-mime") || mimePart.isMimeType("application/x-pkcs7-mime")) {
				return new SMIMESigned(mimePart).getContent();
			} else {
				throw new SmimeException("Message not signed");
			}
		} catch (Exception e) {
			throw handledException(e);
		}
	}

	/**
	 * Returns the S/MIME state of a MIME multipart.
	 * 
	 * @param mimeMultipart
	 *            The {@link MimeMultipart} to be checked.
	 * @return the {@link SmimeState} of the {@link MimeMultipart}.
	 */
	public static SmimeState getStatus(MimeMultipart mimeMultipart) {
		try {
			return getStatus(new ContentType(mimeMultipart.getContentType()));
		} catch (Exception e) {
			throw handledException(e);
		}
	}

	/**
	 * Returns the S/MIME state of a MIME part (i.e. MIME message).
	 * 
	 * @param mimePart
	 *            The {@link MimePart} to be checked.
	 * @return the {@link SmimeState} of the {@link MimePart}.
	 */
	public static SmimeState getStatus(MimePart mimePart) {
		try {
			return getStatus(new ContentType(mimePart.getContentType()));
		} catch (Exception e) {
			throw handledException(e);
		}
	}

	private static SmimeState getStatus(ContentType contentType) {
		try {
			if (isSmimeSignatureContentType(contentType)) {
				return SmimeState.SIGNED;
			} else if (isSmimeEncryptionContenttype(contentType)) {
				return SmimeState.ENCRYPTED;
			} else {
				return SmimeState.NEITHER;
			}
		} catch (Exception e) {
			return SmimeState.NEITHER;
		}
	}

	private static boolean isSmimeEncryptionContenttype(ContentType contentType) {
		String baseContentType = contentType.getBaseType();
		return baseContentType.equalsIgnoreCase("application/pkcs7-mime")
				|| baseContentType.equalsIgnoreCase("application/x-pkcs7-mime");
	}

	private static boolean isSmimeSignatureContentType(ContentType contentType) {
		String baseContentType = contentType.getBaseType();
		return baseContentType.equalsIgnoreCase("multipart/signed")
				&& isSmimeSignatureProtocoll(contentType.getParameter("protocol"));
	}

	private static boolean isSmimeSignatureProtocoll(String protocol) {
		return protocol.equalsIgnoreCase("application/pkcs7-signature")
				|| protocol.equalsIgnoreCase("application/x-pkcs7-signature");
	}

	private static SmimeException handledException(Exception e) {
		if (e instanceof SmimeException) {
			return (SmimeException) e;
		}
		return new SmimeException(e.getMessage(), e);
	}

}
