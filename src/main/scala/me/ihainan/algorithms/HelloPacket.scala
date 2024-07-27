package me.ihainan.algorithms

import org.slf4j.LoggerFactory
import me.ihainan.utils.SSHBuffer
import me.ihainan.SSHSession
import java.io.InputStream

// https://datatracker.ietf.org/doc/html/rfc4253#section-4.2
object HelloPacket {
  private val logger = LoggerFactory.getLogger(getClass().getName())

  private val SSH_CLIENT_VERSON = "SSH-2.0-SimpleSSH_0.0.1"

  def generateVersionPacket(): SSHBuffer = {
    val buffer = new SSHBuffer()
    logger.info(s"  clientSSHVersion = $SSH_CLIENT_VERSON")
    buffer.putByteArray(SSH_CLIENT_VERSON.getBytes())
    buffer.putByte(0x0d.toByte) // CR
    buffer.putByte(0x0a.toByte) // LF
    SSHSession.setClientVersion(SSH_CLIENT_VERSON)
    buffer
  }

  def receiveServerVersionPacket(in: InputStream): Unit = {
    val buffer = collection.mutable.ArrayBuffer.empty[Byte]
    var lastByte: Int = -1
    var currentByte: Int = -1
    var serverVersion: String = null
    while (serverVersion == null && {
        currentByte = in.read; currentByte != -1
      }) {
      if (lastByte == 0x0d && currentByte == 0x0a) {
        buffer.trimEnd(1)
        serverVersion = new String(buffer.toArray)
        logger.info(s"  serverSSHVersion = $serverVersion")
      }
      buffer += currentByte.toByte
      lastByte = currentByte
    }
    SSHSession.setServerVersion(serverVersion)
  }
}
