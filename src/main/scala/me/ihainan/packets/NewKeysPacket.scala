package me.ihainan.packets

import java.io.InputStream
import me.ihainan.utils.SSHBuffer
import me.ihainan.utils.SSHBufferReader
import me.ihainan.utils.SSHStreamBufferReader

// https://datatracker.ietf.org/doc/html/rfc4253#section-7.3
object NewKeysPacket {
  
  val SSH_MSG_NEWKEYS = 0x15.toByte

  def generatePacket(): Array[Byte] = {
    val buffer = new SSHBuffer()
    buffer.putByte(SSH_MSG_NEWKEYS)
    buffer.wrapWithPadding().getData
  }

  def readNewKeysFromInputStream(in: InputStream): Unit = {
    val reader = new SSHStreamBufferReader(in)
    val payloadBuffer = reader.reader
    val paddingLength = payloadBuffer.getByte()
    val newKeyCode = payloadBuffer.getByte()
    if (newKeyCode != SSH_MSG_NEWKEYS) {
      throw new Exception("The received code is not NEW_KEY")
    }
  }
}
