package me.ihainan.packets

import org.slf4j.LoggerFactory
import me.ihainan.utils.SSHBuffer

object DisconnectPacket {
  private val logger = LoggerFactory.getLogger(getClass().getName())
  private val SSH_MSG_DISCONNECT = 1.toByte
  private val REASON_CODE = 11

  def generateDisconnectPacket(): SSHBuffer = {
    val buffer = new SSHBuffer()
    buffer.putByte(SSH_MSG_DISCONNECT)
    buffer.putInt(REASON_CODE)
    buffer.putString("Please close the connection")
    buffer.putString("en")
    buffer.encryptAndAppendMAC()
  }
}
