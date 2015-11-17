# A S/MIME library for JavaMail

[![Build Status](https://travis-ci.org/markenwerk/java-utils-mail-smime.svg?branch=master)](https://travis-ci.org/markenwerk/java-utils-mail-smime)
[![Dependency Status](https://www.versioneye.com/user/projects/562bcd9836d0ab002100128a/badge.svg)](https://www.versioneye.com/user/projects/562bcd9836d0ab002100128a)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/net.markenwerk/utils-mail-smime/badge.svg)](https://maven-badges.herokuapp.com/maven-central/net.markenwerk/utils-mail-smime)

This is a simple to use library to use [S/MIME](https://en.wikipedia.org/wiki/S/MIME) features in conjunction with [JavaMail](http://www.oracle.com/technetwork/java/javamail/index.html).

## Overview

This library allows you to

 - sign MIME Messages according to the S/MIME standard,
 - encrypt MIME Messages according to the S/MIME standard,
 - check, whether a MIME Message is encrypted or signed according to the S/MIME standard,
 - check, whether the signature of a MIME message that is signed according to the S/MIME standard is valid or
 - decrypt a MIME message that is encrypted according to the S/MIME standard.

This library is hosted in the [Maven Central Repositoy](http://search.maven.org/#artifactdetails|net.markenwerk|utils-mail-smime|1.0.2|jar). You can use it with the following coordinates:

```xml
<dependency>
	<groupId>net.markenwerk</groupId>
	<artifactId>utils-mail-smime</artifactId>
	<version>1.0.2</version>
</dependency>
```

Consult the [usage description](#usage) and [Javadoc](http://markenwerk.github.io/java-utils-mail-smime/javadoc/1.0.2/index.html) for further information.

## Origin and state

The initial version of this library is based on the S/MIME specific parts of a project called [JavaMail-Crypto API](http://javamail-crypto.sourceforge.net/) which relies on the Java version of [The Legion of the Bouncy Castle](http://www.bouncycastle.org/java.html) as a provider of all sorts of cryptography witchcraft.  
The JavaMail-Crypto API itself seems to be heavily influenced by the [example code](http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcmail-jdk16/1.46/org/bouncycastle/mail/smime/examples) from the Bouncy Castle project.

We've decided to provide this library as an alternative for the S/MIME specific functionality of the JavaMail-Crypto API since the original project appears to be unmaintained since June of 2006 and is in fact incompatible with more current versions of Bouncy Castle (Some methods were deprecated for years and are now completely removed).  
It is currently not our intention to provide a corresponding modernization of the PGP specific functionality.

The project page of the JavaMail-Crypto API states that it is *currently* in an alpha state. However, we never had any major issues while we were using it in a production environment. Fixes to minor issues have been incorporated in this library.

We used the original - and now this - library mainly to sign and encrypt system generated messages.
None of the major mail clients that actually have S/MIME support (Thunderbird, Mail for Mac & iOS, etc.) had any problems to decrypt or check the signatures of these messages.

This library has roughly the same range of functionality regarding S/MIME as the original library. This may not be every aspect of the current [RFC](https://tools.ietf.org/html/rfc5751), but we're trying to improve this library when necessary. A further goal of this library is to provide an API that is as simple as possible to use.

## Setup

An application that wants to encrypt a S/MIME message has to provide a S/MIME certificate in form of a standard [`X509Certificate`][X509Certificate].
This library imposes no obstacles on how the certificate object is obtained.

An application that wants to sign or decrypt a S/MIME message has to provide a standard [`PrivateKey`][PrivateKey] and the [`X509Certificate`][X509Certificate] chain for the S/MIME certificate, but the preferred way is to provide these as a PKCS12 keystore.

Some CAs provide S/MIME certificates free of charge (i.E. [COMODO](https://secure.comodo.com/products/frontpage?area=SecureEmailCertificate)). In most cases, a private key is created by the browser that is used to apply for the certificate, i.e. by using the [keygen](http://www.w3schools.com/tags/tag_keygen.asp) tag, and after validation, i.e. opening a confirmation link send via email, the corresponding certificate is installed into the browsers certificate store. The private key and the certificate, including the certificate chain, can then be exported as a PKCS12 keystore. The alias given to the private key inside the keystore is usually neither guessable nor very sensible, but you can use the [keytool](https://docs.oracle.com/javase/7/docs/technotes/tools/windows/keytool.html) to find it out.

```shell
keytool -list -storetype pkcs12 -keystore smime.p12
```
	
For a PKCS12 keystore called `smime.p12` this yields a output like

```
Keystore type: PKCS12
Keystore provider: SunJSSE

Your keystore contains 1 entry

's comodo ca limited id, Oct 8, 2015, PrivateKeyEntry, 
Certificate fingerprint (SHA1): F1:A9:99:CC:35:CA:3E:C7:D3:01:EC:95:14:D7:C0:32:1C:AF:50:CF
```
 
where `'s comodo ca limited id` is the given alias. It can be changed like this:

```shell
keytool -changealias -alias "'s comodo ca limited id" -destalias "alias" -storetype pkcs12 -keystore smime.p12
```

The public certificate can be exported into a PEM encoded file like this:

```shell
keytool -export -alias "alias" -storetype pkcs12 -keystore smime.p12 -rfc -file certificate.pem
```
	
## Usage

First things first: The [`BouncyCastleProvider`][BouncyCastleProvider] has to be added as a JCE provider somewhere in your application before this library can be used:

```java
Security.addProvider(new BouncyCastleProvider());
```
	
### Importing the S/MIME certificate ...

Depending on what you want to do with this library you must import the private key and certificate chain as a [`SmimeKey`][SmimeKey] or import the public certificate as a [`X509certificate`][X509Certificate]. 

#### ... to sing or decrypt a message

While [`SmimeKey`][SmimeKey] has a public constructor it is recommended to use a [`SmimeKeyStore`][SmimeKeyStore], which is a thin wrapper around a PKCS12 keystore and can be created and used like this:

```java
SmimeKeyStore smimeKeyStore = new SmimeKeyStore(pkcs12Stream, storePass);
SmimeKey smimeKey = smimeKeyStore.getPrivateKey("alias", keyPass);
```

To create a [`SmimeKeyStore`][SmimeKeyStore] you have to provide an [`InputStream`][InputStream] that yields the PKCS12 keystore (most likely a [`FileInputStream`][FileInputStream]) and the store password as a `char[]`. By default, the `char[]` will be overwritten after is has been used. This behaviour can be turned off with the optional third parameter.

To obtain a [`SmimeKey`][SmimeKey] from the [`SmimeKeyStore`][SmimeKeyStore] you have to provide the alias of the private key entry and the password to decrypt the private key. Again, as a `char[]` that will be overwritten by default.

#### ... to encrypt a message

There are many ways to import a [`X509certificate`][X509Certificate]. One possibility is the following where you have to provide an [`InputStream`][InputStream] that yields the PEM encoded certificate:

```java
CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
X509Certificate certificate = (X509Certificate) factory.generateCertificate(pemStream);
```
	
### Using the library as a sender ...

While is is in theory possible to sign and encrypt a message in any order and even multiple times, this is not recommended in reality because even the common mail clients don't support such usages of S/MIME very well.

So far, we haven't encountered any problems with the following usages:

 - Signing only
 - Encrypting only
 - Fist signing, than encrypting
 
We will assume that you already know how to create a SMTP [`Session`][Session] and how create and send a MIME Message with JavaMail, but here is a minimal example how one could send a simple message:

```java
public void sendMail(Session session, String from, String to, String subject, String content) throws Exception {
	MimeMessage message = new MimeMessage(session);
	message.setFrom(new InternetAddress(from));
	message.setRecipient(RecipientType.TO, new InternetAddress(to));
	message.setSubject(subject);
	message.setContent(content, "text/plain; charset=utf-8");
	MimeMessage encryptedSignedMessage = encryptMessage(session, signMessage(session, message, from), to);
	Transport.send(encryptedSignedMessage);
}
```

#### .. to sign a message

Just use the [`SmimeUtil`][SmimeUtil] with the [`MimeMessage`][MimeMessage] to be signed and the [`SmimeKey`][SmimeKey] to sign it with:

```java
private MimeMessage signMessage(Session session, MimeMessage message, String from) throws Exception {
	SmimeKey smimeKey = getSmimeKeyForSender(from);
	return SmimeUtil.sign(session, message, smimeKey);
}
```

#### .. to encrypt a message

Just use the [`SmimeUtil`][SmimeUtil] with the [`MimeMessage`][MimeMessage] to be encrypted and the [`X509certificate`][X509Certificate] to encrypt it with:

```java
private MimeMessage encryptMessage(Session session, MimeMessage message, String to) throws Exception {
	X509Certificate certificate = getCertificateForRecipient(to);
	return SmimeUtil.encrypt(session, message, certificate);
}
```

### Using the library as a receiver

We will assume that you already know how to create a POP or IMAP [`Session`][Session] and how receive a MIME Message with JavaMail, but here is a minimal example how one could read messages:

```java
Store store = session.getStore();
store.connect(host, port, user, password);
Folder inbox = store.getFolder("Inbox");
inbox.open(Folder.READ_ONLY);

for (int i = 1, n = inbox.getMessageCount(); i <= n; i++) {
	MimeMessage mimeMessage = (MimeMessage) inbox.getMessage(i);
}
```
	
You can then use the [`SmimeUtil`][SmimeUtil] check the messages content type and find out if it has a [`SmimeState`][SmimeState] of `ENCRYPTED`, `SIGNED` or `NEITHER` like this:

```java
SmimeState smimeState = SmimeUtil.getStatus(mimePart);
```
	
If the messages S/MIME state is `ENCRYPTED`, you can use the [`SmimeUtil`][SmimeUtil] with the encrypted [`MimeMessage`][MimeMessage] and the [`SmimeKey`][SmimeKey] to decrypt like this:

```java
MimeMessage decryptedMessage = SmimeUtil.decrypt(session, mimeMessage, getSmimeKey());
```
	
If the messages S/MIME state is `SIGNED` (the contains a MIME multipart with exactly two body parts: the signed content and the signature), you can use the [`SmimeUtil`][SmimeUtil] to check whether the signature is valid for the signed content and retrieve the signed content like this:

```java
boolean validSignature = SmimeUtil.checkSignature(mimePart)
MimeBodyPart signedContent = SmimeUtil.getSignedContent(mimePart);
```

If the messages S/MIME state is `NEITHER` it just means that the message is neither S/MIME encrypted nor S/MIME signed. It may be encrypted or signed by some other means.

[BouncyCastleProvider]: http://www.bouncycastle.org/docs/docs1.5on/index.html?org/bouncycastle/jce/provider/BouncyCastleProvider.html
[FileInputStream]: http://docs.oracle.com/javase/7/docs/api/index.html?java/io/FileInputStream.html
[InputStream]: http://docs.oracle.com/javase/7/docs/api/index.html?java/io/InputStream.html
[MimeMessage]: http://javamail.java.net/nonav/docs/api/index.html?javax/mail/internet/MimeMessage.html
[PrivateKey]: http://docs.oracle.com/javase/7/docs/api/index.html?java/security/PrivateKey.html
[Session]: http://javamail.java.net/nonav/docs/api/index.html?javax/mail/Session.html
[SmimeKey]: http://markenwerk.github.io/java-utils-mail-smime/javadoc/1.0.2/index.html?net/markenwerk/utils/mail/smime/SmimeKey.html
[SmimeKeyStore]: http://markenwerk.github.io/java-utils-mail-smime/javadoc/1.0.2/index.html?net/markenwerk/utils/mail/smime/SmimeKeyStore.html
[SmimeState]: http://markenwerk.github.io/java-utils-mail-smime/javadoc/1.0.2/index.html?net/markenwerk/utils/mail/smime/SmimeState.html
[SmimeUtil]: http://markenwerk.github.io/java-utils-mail-smime/javadoc/1.0.2/index.html?net/markenwerk/utils/mail/smime/SmimeUtil.html
[X509Certificate]: http://docs.oracle.com/javase/7/docs/api/index.html?java/security/cert/X509Certificate.html
