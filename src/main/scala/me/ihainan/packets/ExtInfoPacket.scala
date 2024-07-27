package me.ihainan.packets

import java.io.InputStream
import me.ihainan.utils.SSHEncryptedStreamBufferReader
import me.ihainan.utils.SSHFormatter
import org.slf4j.LoggerFactory

// https://datatracker.ietf.org/doc/html/rfc8308
// https://github.com/apache/mina-sshd/blob/4b30ab065d065a9b85a8b5f65df0d6ad111fae3c/sshd-core/src/main/java/org/apache/sshd/common/session/helpers/AbstractSession.java#L736
object ExtInfoPacket {
  private val logger = LoggerFactory.getLogger(getClass().getName())

  def readExtInfoPacket(in: InputStream): Unit = {
    val reader = new SSHEncryptedStreamBufferReader(in)
    val payloadBuffer = reader.reader
    val paddingLength = payloadBuffer.getByte()
    val command = payloadBuffer.getByte()
    val listSize = payloadBuffer.getInt()
    logger.debug("  ExtInfoPacket: " + SSHFormatter.formatByteArray(payloadBuffer.getData()))
    logger.debug("  ExtInfoPacket padding length: " + paddingLength)
    logger.debug("  ExtInfoPacket command: " + command)
    logger.debug("  ExtInfoPacket list size: " + listSize)
    (0 until listSize).foreach { i =>
      val key = payloadBuffer.getString()
      val value = payloadBuffer.getString()
      logger.debug(s"  ExtInfoPacket info($i): " + key + " = " + value)
    }
  }
}
