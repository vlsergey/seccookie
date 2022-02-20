# Secure Cookie Library
Java library for security cookies, client-side pieces of data protected from reading and modifications by client with strong cryptography

* Allows to store small pieces of data at client side protected from reading **and modifications** by client and by third party.
* Uses strong encryption ([AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) with [GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)) to encrypt, decipher and validate data.
* Has no runtime dependencies, plain JDK is enough.

[![Build with Gradle](https://github.com/vlsergey/seccookie/actions/workflows/build.yml/badge.svg)](https://github.com/vlsergey/seccookie/actions/workflows/build.yml)
[![CodeQL](https://github.com/vlsergey/seccookie/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/vlsergey/seccookie/actions/workflows/codeql-analysis.yml)

## Installation

### Gradle

```groovy
dependencies {
  implementation group: 'io.github.vlsergey', name: 'seccookie', version: '${version}'
}
```

### Maven

```xml
  <dependency>
    <groupId>io.github.vlsergey</groupId>
    <artifactId>seccookie</artifactId>
    <version>${version}</version>
  </dependency>
```

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

## Key rolling technique
For long living and secure-oriented systems it may be required to provide a "key rolling" support where keys can be replaced in runtime without problems with existing user data. `SimpleSecCookieMapper` supports it via providing list of keys that can be used to try and decrypt secure cookie. All keys will be used in provided order and only after all of them tried single success result will be returned. I.e. there is no "fast first success" shortcut to prevent timing attacks (but at the cost of exception creation in JVM).

To provide multiple decryption key just set `decryptionKeysSupplier` property in `SimpleSecCookieMapper.Settings`:

```java
SimpleSecCookieMapper.Settings settings = new SimpleSecCookieMapper.Settings(
   serializer, deserializer, secretKeySupplier);
settings.setDecryptionKeysSupplier = () -> Arrays.asList( secretKey1, secretKey2, secretKey3, ... );
```

There are 2 rules when changing keys configuration:
* Encrypt with newest key.
* Have all old keys in decryption keys list until keys/cookie TTL expired.

Assume we have configuration alike following:

```yaml
encryptWith: secretKey2
decryptWith:
  - secretKey1
  - secretKey2
```

`secretKey1` was used long time before. So we removing it from the list and add new `secretKey3` to decryption keys list:

```yaml
encryptWith: secretKey2
decryptWith:
  - secretKey2
  - secretKey3
```

After that (or at the same time -- it's safe to do it simultaneously) one need to replace encryption key with new one:

```yaml
encryptWith: secretKey3
decryptWith:
  - secretKey2
  - secretKey3
```

Just make sure that encryption key is always somewhere in the list of decryption keys.
