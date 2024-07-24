package me.ihainan

import scala.util.Random
import java.io.{ByteArrayInputStream, InputStream}
import java.nio.ByteBuffer
import org.apache.commons.codec.binary.Hex;

class AlgorithmNegotiationPacket(
    val cookie: Array[Byte],
    val keyExchangeAlgorithms: String,
    val serverHostKeyAlgorithms: String,
    val encryptionAlgorithmsClientToServer: String,
    val encryptionAlgorithmsServerToClient: String,
    val macAlgorithmsClientToServer: String,
    val macAlgorithmsServerToClient: String,
    val compressionAlgorithmsClientToServer: String,
    val compressionAlgorithmsServerToClient: String,
    val languagesClientToServer: String,
    val languagesServerToClient: String,
    val firstKexPacketFollows: Byte
) {
  private val SSH_MSG_KEXINIT = 0x14.toByte
  private val random = new Random()
  private val reserved = SSHUtils.intToBytes(0)
  private var payloadByteArray: Array[Byte] = _

  override def toString(): String = {
    val sb = new StringBuilder()
    sb.append("  cookie = " + SSHUtils.formatByteArray(cookie) + "\n")
    sb.append("  keyExchangeAlgorithms = " + keyExchangeAlgorithms + "\n")
    sb.append("  serverHostKeyAlgorithms = " + serverHostKeyAlgorithms + "\n")
    sb.append("  encryptionAlgorithmsClientToServer = " + encryptionAlgorithmsClientToServer + "\n")
    sb.append("  encryptionAlgorithmsServerToClient = " + encryptionAlgorithmsServerToClient + "\n")
    sb.append("  macAlgorithmsClientToServer = " + macAlgorithmsClientToServer + "\n")
    sb.append("  macAlgorithmsServerToClient = " + macAlgorithmsServerToClient + "\n")
    sb.append(
      "  compressionAlgorithmsClientToServer = " + compressionAlgorithmsClientToServer + "\n")
    sb.append(
      "  compressionAlgorithmsServerToClient = " + compressionAlgorithmsServerToClient + "\n")
    sb.append("  languagesClientToServer = " + languagesClientToServer + "\n")
    sb.append("  languagesServerToClient = " + languagesServerToClient + "\n")
    sb.append("  firstKexPacketFollows = " + firstKexPacketFollows + "\n")
    sb.toString()
  }

  /** Get the byte array of the payload part
    *
    * @return
    *   byte array of the payload
    */
  def getPayloadByteArray(): Array[Byte] = {
    val bytes = collection.mutable.ArrayBuffer.empty[Byte]

    // SSH_MSG_KEXINIT
    bytes += SSH_MSG_KEXINIT

    // cookie
    bytes.appendAll(cookie)

    // algorithms
    Array(
      keyExchangeAlgorithms,
      serverHostKeyAlgorithms,
      encryptionAlgorithmsClientToServer,
      encryptionAlgorithmsServerToClient,
      macAlgorithmsClientToServer,
      macAlgorithmsServerToClient,
      compressionAlgorithmsClientToServer,
      compressionAlgorithmsServerToClient,
      languagesClientToServer,
      languagesServerToClient
    ).foreach { algorithm =>
      SSHUtils.appendStringWithLength(bytes, algorithm)
    }

    // firstKexPacketFollows
    bytes += firstKexPacketFollows

    // reserved
    bytes.appendAll(reserved)

    bytes.toArray
  }

  def toFullBytes(): Array[Byte] = {
    val bytes = collection.mutable.ArrayBuffer.empty[Byte]

    // payload and padding
    payloadByteArray = getPayloadByteArray()
    val payloadLength = payloadByteArray.length
    val paddingLength = SSHUtils.calculatePaddingLength(payloadLength, blockSize = 8)
    val paddings = (0 until paddingLength).map(_ => 0.toByte)

    // packet length
    val packetLength = payloadLength + paddingLength + 1
    bytes.appendAll(SSHUtils.intToBytes(packetLength))
    println(
      s"payloadLength = $payloadLength, paddingLength = $paddingLength, packetLength = $packetLength")

    // padding length
    bytes += paddingLength.toByte

    // payload
    bytes.appendAll(payloadByteArray)

    // paddings
    bytes.appendAll(paddings)

    // result
    bytes.toArray
  }
}

object AlgorithmNegotiationPacket {
  val cookie = Array(0x6f, 0x34, 0x3a, 0xdc, 0x69, 0x15, 0x84, 0x4a, 0x9d,
    0x84, 0x2d, 0x36, 0x4c, 0x9c, 0xee, 0xcb).map(_.toByte)
  val keyExchangeAlgorithms =
    "diffie-hellman-group14-sha256,ext-info-c,kex-strict-c-v00@openssh.com"
  val serverHostKeyAlgorithms =
    "rsa-sha2-512"
  val encryptionAlgorithmsClientToServer =
    "aes256-ctr"
  val encryptionAlgorithmsServerToClient =
    "aes256-ctr"
  val macAlgorithmsClientToServer =
    "hmac-sha2-256"
  val macAlgorithmsServerToClient =
    "hmac-sha2-256"
  val compressionAlgorithmsClientToServer = "none,zlib@openssh.com,zlib"
  val compressionAlgorithmsServerToClient = "none,zlib@openssh.com,zlib"
  val languagesClientToServer = ""
  val languagesServerToClient = ""
  val firstKexPacketFollows = 0.toByte

  def getClientAlgorithms(): AlgorithmNegotiationPacket = {
    val clientAlgorithms = new AlgorithmNegotiationPacket(
      cookie = cookie,
      keyExchangeAlgorithms = keyExchangeAlgorithms,
      serverHostKeyAlgorithms = serverHostKeyAlgorithms,
      encryptionAlgorithmsClientToServer = encryptionAlgorithmsClientToServer,
      encryptionAlgorithmsServerToClient = encryptionAlgorithmsServerToClient,
      macAlgorithmsClientToServer = macAlgorithmsClientToServer,
      macAlgorithmsServerToClient = macAlgorithmsServerToClient,
      compressionAlgorithmsClientToServer = compressionAlgorithmsClientToServer,
      compressionAlgorithmsServerToClient = compressionAlgorithmsServerToClient,
      languagesClientToServer = languagesClientToServer,
      languagesServerToClient = languagesServerToClient,
      firstKexPacketFollows = firstKexPacketFollows
    )
    clientAlgorithms
  }

  def readAlgorithmsFromInputStream(in: InputStream): AlgorithmNegotiationPacket = {
    val packetLength = SSHUtils.readInt(in)
    val paddingLength = in.read()
    val payloadLength = packetLength - 1
    val payload = SSHUtils.readByteArray(in, payloadLength)
    val messageCode = payload.slice(0, 1)
    val cookie = payload.slice(1, 17)
    // println(s"Message code = ${SSHUtils.formatByteArray(messageCode)}")
    // println(s"cookie = ${SSHUtils.formatByteArray(cookie)}")
    val stringReader = new StringReader(payload.slice(17, payload.length))
    val keyExchangeAlgorithms = stringReader.next()
    val serverHostKeyAlgorithms = stringReader.next()
    val encryptionAlgorithmsClientToServer = stringReader.next()
    val encryptionAlgorithmsServerToClient = stringReader.next()
    val macAlgorithmsClientToServer = stringReader.next()
    val macAlgorithmsServerToClient = stringReader.next()
    val compressionAlgorithmsClientToServer = stringReader.next()
    val compressionAlgorithmsServerToClient = stringReader.next()
    val languagesClientToServer = stringReader.next()
    val languagesServerToClient = stringReader.next()
    val firstKexPacketFollows = payload(17 + stringReader.getIndex)

    new AlgorithmNegotiationPacket(
      cookie,
      keyExchangeAlgorithms,
      serverHostKeyAlgorithms,
      encryptionAlgorithmsClientToServer,
      encryptionAlgorithmsServerToClient,
      macAlgorithmsClientToServer,
      macAlgorithmsServerToClient,
      compressionAlgorithmsClientToServer,
      compressionAlgorithmsServerToClient,
      languagesClientToServer,
      languagesServerToClient,
      firstKexPacketFollows
    )
  }
}
