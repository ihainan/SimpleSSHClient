package me.ihainan.packets

import java.io.InputStream
import me.ihainan.utils.SSHBuffer
import me.ihainan.utils.SSHBufferReader
import me.ihainan.utils.SSHStreamBufferReader

// https://datatracker.ietf.org/doc/html/rfc4253#section-7.3
object NewKeyPacket {
  
  val NEW_KEY = 0x15.toByte

  def generatePacket(): Array[Byte] = {
    val buffer = new SSHBuffer()
    buffer.putByte(NEW_KEY)
    buffer.wrapWithPadding().getData
  }

  def readNewKeyFromInputStream(in: InputStream): Unit = {
    val reader = new SSHStreamBufferReader(in)
    val payloadBuffer = reader.reader
    val paddingLength = payloadBuffer.getByte()
    val newKeyCode = payloadBuffer.getByte()
    if (newKeyCode != NEW_KEY) {
      throw new Exception("The received code is not NEW_KEY")
    }
  }
}
