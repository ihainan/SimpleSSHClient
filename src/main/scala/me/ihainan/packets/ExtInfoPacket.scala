package me.ihainan.packets

import java.io.InputStream
import me.ihainan.utils.SSHEncryptedStreamBufferReader
import me.ihainan.utils.SSHFormatter

// https://tools.ietf.org/html/rfc8308#section-2.4
// https://github.com/apache/mina-sshd/blob/4b30ab065d065a9b85a8b5f65df0d6ad111fae3c/sshd-core/src/main/java/org/apache/sshd/common/session/helpers/AbstractSession.java#L736
object ExtInfoPacket {
  def readExtInfoPacket(in: InputStream): Unit = {
    val reader = new SSHEncryptedStreamBufferReader(in)
    val payloadBuffer = reader.reader
    val paddingLength = payloadBuffer.getByte()
    val command = payloadBuffer.getByte()
    val listSize = payloadBuffer.getInt()
    println("  ExtInfoPacket: " + SSHFormatter.formatByteArray(payloadBuffer.getData()))
    println("  ExtInfoPacket padding length: " + paddingLength)
    println("  ExtInfoPacket command: " + command)
    println("  ExtInfoPacket list size: " + listSize)
    (0 until listSize).foreach { i =>
      val key = payloadBuffer.getString()
      val value = payloadBuffer.getString()
      println(s"  ExtInfoPacket info($i): " + key + " = " + value)
    }

  }
}
