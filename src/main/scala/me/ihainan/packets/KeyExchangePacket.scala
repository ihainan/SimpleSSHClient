package me.ihainan.packets

import scala.util.Random
import java.io.{ByteArrayInputStream, InputStream}
import java.nio.ByteBuffer
import org.apache.commons.codec.binary.Hex;
import me.ihainan.utils.SSHBuffer
import me.ihainan.utils.SSHStreamBufferReader
import me.ihainan.utils.SSHBufferReader
import me.ihainan.SSHSession
import org.slf4j.LoggerFactory
import me.ihainan.utils.SSHFormatter

// https://datatracker.ietf.org/doc/html/rfc4253#section-7
class KeyExchangePacket(
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
  private val logger = LoggerFactory.getLogger(getClass().getName())
  import KeyExchangePacket._

  private val random = new Random()

  override def toString(): String = {
    val sb = new StringBuilder()
    sb.append(s" cookie = ${SSHFormatter.formatByteArray(cookie)}\n")
    sb.append(s" keyExchangeAlgorithms = $keyExchangeAlgorithms\n")
    sb.append(s" serverHostKeyAlgorithms = $serverHostKeyAlgorithms\n")
    sb.append(s" encryptionAlgorithmsClientToServer = $encryptionAlgorithmsClientToServer\n")
    sb.append(s" encryptionAlgorithmsServerToClient = $encryptionAlgorithmsServerToClient\n")
    sb.append(s" macAlgorithmsClientToServer = $macAlgorithmsClientToServer\n")
    sb.append(s" macAlgorithmsServerToClient = $macAlgorithmsServerToClient\n")
    sb.append(s" compressionAlgorithmsClientToServer = $compressionAlgorithmsServerToClient\n")
    sb.append(s" languagesClientToServer = $languagesClientToServer\n")
    sb.append(s" languagesServerToClient = $languagesServerToClient\n")
    sb.append(s" firstKexPacketFollows = $firstKexPacketFollows\n")
    sb.toString()
  }

  def generatePayload(): SSHBuffer = {
    val buffer = new SSHBuffer()
    buffer.putByte(SSH_MSG_KEXINIT)
    buffer.putByteArray(cookie)
    for (algorithm <- clientAlgorithms) {
      buffer.putString(algorithm)
    }
    buffer.putByte(firstKexPacketFollows)
    buffer.putInt(reserved)
    buffer
  }

  def generatePacket(): SSHBuffer = {
    val payloadBuffer = generatePayload()
    SSHSession.setIC(payloadBuffer.getData) // IC contains the SSH_MSG_KEXINIT
    val buffer = payloadBuffer.wrapWithPadding()
    buffer
  }
}

object KeyExchangePacket {
  private val logger = LoggerFactory.getLogger(getClass().getName())
  
  private val SSH_MSG_KEXINIT = 0x14.toByte
  val cookie = Array(0x6f, 0x34, 0x3a, 0xdc, 0x69, 0x15, 0x84, 0x4a, 0x9d,
    0x84, 0x2d, 0x36, 0x4c, 0x9c, 0xee, 0xcb).map(_.toByte)
  val keyExchangeAlgorithms =
    "diffie-hellman-group14-sha256,ext-info-c,kex-strict-c-v00@openssh.com"
  val serverHostKeyAlgorithms = "rsa-sha2-512"
  val encryptionAlgorithmsClientToServer = "aes256-ctr"
  val encryptionAlgorithmsServerToClient = "aes256-ctr"
  val macAlgorithmsClientToServer = "hmac-sha1"
  val macAlgorithmsServerToClient = "hmac-sha1"
  val compressionAlgorithmsClientToServer = "none"
  val compressionAlgorithmsServerToClient = "none"
  val languagesClientToServer = ""
  val languagesServerToClient = ""
  val firstKexPacketFollows = 0.toByte
  val clientAlgorithms = Array(
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
  )
  val reserved: Int = 0

  def getClientAlgorithms(): KeyExchangePacket = {
    val clientAlgorithms = new KeyExchangePacket(
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

  def readAlgorithmsFromInputStream(in: InputStream): KeyExchangePacket = {
    // parse packet
    val streamReader = new SSHStreamBufferReader(in)
    val reader = streamReader.reader
    val packetLength = streamReader.packetLength
    val paddingLength = reader.getByte()
    val payloadBytes = reader.getByteArray(packetLength - paddingLength - 1)
    val payloadReader = new SSHBufferReader(payloadBytes)

    // Save into SSHSession
    SSHSession.setIS(payloadBytes)

    // read payload
    val command = payloadReader.getByte()
    logger.debug(s"  packet command = $command")
    val cookie = payloadReader.getByteArray(16)
    val keyExchangeAlgorithms = payloadReader.getString()
    val serverHostKeyAlgorithms = payloadReader.getString()
    val encryptionAlgorithmsClientToServer = payloadReader.getString()
    val encryptionAlgorithmsServerToClient = payloadReader.getString()
    val macAlgorithmsClientToServer = payloadReader.getString()
    val macAlgorithmsServerToClient = payloadReader.getString()
    val compressionAlgorithmsClientToServer = payloadReader.getString()
    val compressionAlgorithmsServerToClient = payloadReader.getString()
    val languagesClientToServer = payloadReader.getString()
    val languagesServerToClient = payloadReader.getString()
    val firstKexPacketFollows = payloadReader.getByte()

    new KeyExchangePacket(
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
