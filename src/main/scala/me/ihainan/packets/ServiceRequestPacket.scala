package me.ihainan.packets

import me.ihainan.utils.SSHBuffer
import java.io.InputStream
import me.ihainan.utils.SSHEncryptedStreamBufferReader
import org.slf4j.LoggerFactory

// https://datatracker.ietf.org/doc/html/rfc4253#section-10
object ServiceRequestPacket {
  private val logger = LoggerFactory.getLogger(getClass().getName())
  
  private val SSH_MSG_SERVICE_REQUEST = 0x05.toByte
  private val SSH_MSG_SERVICE_ACCEPT = 0x06.toByte

  def generateServiceRequestPacket(service: String): SSHBuffer = {
    val buffer = new SSHBuffer()
    buffer.putByte(SSH_MSG_SERVICE_REQUEST)
    buffer.putString(service)
    buffer.encryptAndAppendMAC()
  }

  def receiveServiceAccept(in: InputStream): Unit = {
    val reader = new SSHEncryptedStreamBufferReader(in)
    val payloadBuffer = reader.reader
    val paddingLength = payloadBuffer.getByte()
    val cmd = payloadBuffer.getByte()
    if (cmd != SSH_MSG_SERVICE_ACCEPT) {
      throw new Exception(s"Unexpected cmd $cmd, expect $SSH_MSG_SERVICE_ACCEPT")
    }
    val serviceName = payloadBuffer.getString()
    logger.debug(s"  serviceName = $serviceName")
  }
}
