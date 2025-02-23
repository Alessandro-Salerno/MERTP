# Minimal Encrypted Remote Terminal Protocol
MERTP is a simple TCP-based protocol that allows basic [Canonical Mode](https://www.gnu.org/software/libc/manual/html_node/Canonical-or-Not.html) CLI applications to run on remote servers with multiple connected clients all running  separete instances or sessions of the application.

This repository contains an extensive description of the protocol and a set of software modules in Java that may be used to build both server-side and client-side software making use of MERTP.

## Encapsulation and encoding
All MERTP messages are framed using a technique similar to that of [FramedTCP](https://github.com/Alessandro-Salerno/FramedTCP). Every message exchanged **after the initial handshake** is prefixed with its length in bytes stored as a network-ordered 4-byte integer.
| Offset | Size | Field | Value |
| - | - | - | - |
| 0 | 4 | Message length in bytes | N |
| 4 | N | AES Encrypted message | |

Some rules also apply to the content being exchanged:
- All text elements are encoded in [UTF-8](https://en.wikipedia.org/wiki/UTF-8) using `LF` line separators
- All integers exchanged are in network order

## Connection and handshake
The establishment of a MERTP connection occurs in two steps:
1. The client sends a message to the server containing its public key
2. The server replies with its name, its public key and the AES key (encrypted using the client's public key)

### Client handshake message
| Offset | Size | Field | Value |
| - | - | - | - |
| 0 | 5 | MERTP prefix | `MERTP` |
| 5 | 2 | Version magic | `0x2710` |
| 7 | 4 | Byte length of the key | N |
| 11 | N | X509 4096-bit RSA public key | |

### Server handshake message
| Offset | Size | Field | Value |
| - | - | - | - |
| 0 | 5 | MERTP prefix | `MERTP` |
| 5 | 2 | Version magic | `0x2710` |
| 7 | 4 | Byte length of the server's name | N |
| 11 | N | Server name | |
| 11 + N | 4 | Byte length of the key | M |
| 15 + N | M | X509 4096-bit RSA public key | |
| 15 + N + M | 512 | RSA-encrypted 256-bit AES/CBC/PKCS5Padding key | |
| 527 + N + M | 512 | RSA-encrypted 16-byte AES/CBC/PKCS5Padding IV | |

### Error handling policy
- Handshake messages that lack the "MERTP" prefix should be treated as malformed
- In case of malformed handshake messages or mismatched version numbers, the TCP connection should be closed

## Post-handshake text protocol
After the initial handshake has completed succesfully, the channel switches to a fully text-based encrypted protocol that makes use of the framing system described [above](##Encapsulation-and-encoding).

Messages follow the structure:

| Status | Section | Format | Description |
| - | - | - |  -|
| Mandatory | Message type | Single line uppercase text | Used to identify the structure and contents of the following sections |
| Optional | Headers | `<Key>:<Value>` | Used to send organized information. Data after the colon is _escaped_ using the Java standard |
| Optional |Separator | One line containing only the `LF` character (Empty line) | Used to separate the header and payload sections. Only present if the payload section is present |
| Optional | Payload | | Optional unescaped, unformatted data |

For example, the server could send a `READ` message like so:
```
READ
Input-Type:Text
```
Or it could send a `PRINT` message like so:
```
PRINT

Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
```

## Message types
| Message type | Sender | Description
| - | - | - |
| `PRINT` | Server | Tells the client to display the text present in the payload as a normal canonical mode program would |
| `READ` | Server | Tells the client to read take one element from the input queue or prompt the user if the queue is empty |
| `BUFFER PUSH` | Server | Pushes a message onto the client's input queue to be used for future `READ`s |
| `REDIRECT` | Server | Redirects the client to another MERTP server (used in network setups) |
| `ANSWER` | Client | The client's reply to a `READ` message |
| `DISCONNECT` | Client/Server | Tells the other party that the sender is no longer listening and the connection can be closed safely |

### `PRINT`
This message type has no standard headers.

The data in the payload section is to be displayed directly by the client with minimal manipulation.

### `READ`
| Header | Type | Possible values | Description |
| - | - | - | - |
| `Input-Type` | Text | `Text`, `Password` | Tells the client wether the user is being asked to insert a password or normal text |

**NOTE:** The client is supposed to be transparent. No special text or info messages should be displayed before, after, or during user input.

**NOTE:** For security reasons, the client is supposed to ignore the input queue when the server reads a password.

This message type has no standard payload.

### `BUFFER PUSH`
| Header | Type | Possible values | Description |
| - | - | - | - |
| `Content` | Text | | The content to be pushed into the input queue |

This message type has no standard payload.

### `REDIRECT`
| Header | Type | Possible values | Description |
| - | - | - | - |
| `Server-Address` | Text | | The IP address or domain name of the new server |
| `Server-Port` | Integer | | The port on which the new MERTP is listening for incoming connections |

This message type has no standard payload.

### `ANSWER`
| Header | Type | Possible values | Description |
| - | - | - | - |
| `Content` | Text | | The content read by the client |

This message type has no standard payload.

### `DISCONNECT`
This message type has no standard headers.

This message type has no standard payload.

## Using the protocol
The recommended way to implement MERTP in an application is to use the software provided in this repository. Specifically, `LibMERTP` can help speed up development of MERTP applications in Java.

### Server example
```java
 try (Socket socket = new Socket("localhost", 8000)) {
    final InputStream is = socket.getInputStream();
    final OutputStream os = socket.getOutputStream();

    // Use LibMERTP to read the client's initial request
    final PublicKey clientKey = LibMERTP.readClientHandshake(is);

    // Use LibMERTP to generate the cryptographic keys
    // NOTE: LibMERTP internally uses Java's cryptography API
    final KeyPair serverKeys = LibMERTP.Crypto.rsaNewKeyPair();
    final MERTPSymAESKey aes = LibMERTP.Crypto.aesNewKey();

    // Use LibMERTP to reply with the server's data
    LibMERTP.writeServerHandshake(os, "Example Server", clientKey, serverKeys, aes);

    // All communication should now go through the MERTPChannel object relatedd to this connection
    final MERTPChannel channel = new MERTPChannel(serverKeys, clientKey, aes, is, os);

    // Exchange messages
    channel.writeMessage(LibMERTP.newPrintMsg("Hello, world!"));
    channel.writeMessage(LibMERTP.newReadMsg(LibMERTP.InputTypes.TEXT));
    MERTPMessage reply = channel.readMessage();

    if (reply.isOfType(LibMERTP.MessageTypes.ANSWER)) {
        System.out.println(reply.getHeader("Content"));
    }
} catch (Exception e) {
  throw new RuntimeException(e);
}
```

### Client example
```java
 try (ServerSocket serverSocket = new ServerSocket(8000)) {
    final Socket socket = serverSocket.accept();
    final InputStream is = socket.getInputStream();
    final OutputStream os = socket.getOutputStream();

    // Use LibMERTP to generate the cryptographic keys
    // NOTE: LibMERTP internally uses Java's cryptography API
    final KeyPair clientKeys = LibMERTP.Crypto.rsaNewKeyPair();

    // Use LibMERTP to write the client's initial request
    LibMERTP.writeClientHandshake(os, clientKeys.getPublic())

    // Use LibMERTP to read the server's handshake reply
    MERTPServerHandshake server = LibMERTP.readServerHandshake(is, clientKeys);

    // All communication should now go through the MERTPChannel object relatedd to this connection
    final MERTPChannel channel = new MERTPChannel(serverKeys, clientKey, aes, is, os);

    // Handle incoming messages
    LOOP: while (true) {
        MERTPMessage msg = channel.readMessage();

        switch (msg.getMessageType()) {
            case LibMERTP.MessageTypes.PRINT -> System.out.print(msg.getPayload());
            case LibMERTP.MessageTypes.READ -> {
                // NOTE: This implementation ignores password protection and input queue!
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                channel.writeMessage(LibMERTP.newAnswerMsg(reader.readLine()));
            }
        }
    }
} catch (MERTPVersionMismatchException | MERTPMalformedHandshakeException |
         MERTPServerAuthenticationException e) {
    System.out.println(e.getMessage());
    System.exit(-1);
}
```

### Installing LibMERTP with Maven
After downloading the JAR and placing it in some project directory (e.g., resources), use the following dependency structure in your `pom.xml` file:
```xml
<dependency>
    <groupId>alessandrosalerno.libmertp</groupId>
    <artifactId>LibMERTP</artifactId>
    <version>1.0.0</version>
    <scope>system</scope>
    <systemPath>${project.basedir}/src/main/resources/LibMERTP-1.0.0.jar</systemPath>
</dependency>
```

## Note of caution
Just because something is _encrypted_, it doesn't mean its _secure_.

MERTP currently misses server authentication features and my knowledge of cryptography is too basic to guarantee there's no holes in the protocol. Be ware!

## License
All files in this repository are distributed under the Apache License 2.0. See [LICENSE](LICENSE) for more information.
