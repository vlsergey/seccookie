# Secure Cookie Library
Java library for security cookies, client-side pieces of data protected from reading and modifications by client with strong cryptography

* Allows to store small pieces of data at client side protected from reading **and modifications** by client and by third party.
* Uses strong encryption ([AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) with [GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)) to encrypt, decipher and validate data.
* Has no runtime dependencies, plain JDK is enough.

[![Build with Gradle](https://github.com/vlsergey/seccookie/actions/workflows/build.yml/badge.svg)](https://github.com/vlsergey/seccookie/actions/workflows/build.yml)
[![CodeQL](https://github.com/vlsergey/seccookie/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/vlsergey/seccookie/actions/workflows/codeql-analysis.yml)

## Simple usage (`SimpleSecCookieMapper`)
```java

// Define a way to obtain SecretKey. Usually it is part of application configuration.
// Note. It's better to store SecretKey instance in memory than recreating it from char[] or byte[] on each call.
SecretKey secretKey = /* ... */;
Supplier<SecretKey> secretKeySupplier = () -> secretKey;

// Define a way to (de)serialize your data type to/from byte array.
// It may be Java serialization, Jackson ObjectMapper call for complex objects, or simple getBytes() for Strings:
Function<String, byte[]> serializer = String::getBytes;
Function<byte[], String> deserializer = String::new;

// Construct instance of SimpleSecCookieMapper
SimpleSecCookieMapper.Settings settings = new SimpleSecCookieMapper.Settings(
   serializer, deserializer, secretKeySupplier);
SimpleSecCookieMapper mapper = new SimpleSecCookieMapper(settings);

// use mapper to serialize to secure cookie

String dataToStoreInCookie = UUID.randomUUID().toString();
byte[] secCookie = mapper.writeValue( dataToStoreInCookie );

// sometimes one need to serialize it to String.
// We recommend `apache-codec` library for that:
String encoded = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(secCookie)

// Decoding and validation is quite straightforward
byte[] secCookie2 = org.apache.commons.codec.binary.Base64.decodeBase64( encoded )
try {
  return mapper.readValue(secCookie2);
} catch (WrongSecureCookieException exc) {
  // can be replaced with ControllerAdvice Exception handler
  throw RuntimeException("Supplied data is invalid", exc);
}
```
