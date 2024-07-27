package me.ihainan.packets

import me.ihainan.utils.SSHBuffer
import me.ihainan.utils.SSHEncryptedStreamBufferReader
import java.io.InputStream

// https://www.rfc-editor.org/rfc/rfc4254
class ChannelPacket {
  private val SSH_MSG_CHANNEL_OPEN = 90.toByte
  private val SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91.toByte
  private val SSH_MSG_CHANNEL_WINDOW_ADJUST = 93.toByte
  private val SSH_MSG_CHANNEL_DATA = 94.toByte
  private val SSH_MSG_CHANNEL_EOF = 96.toByte
  private val SSH_MSG_CHANNEL_CLOSE = 97.toByte
  private val SSH_MSG_CHANNEL_REQUEST = 98.toByte
  private val SSH_MSG_CHANNEL_SUCCESS = 99.toByte
  private val SSH_MSG_CHANNEL_FAILURE = 100.toByte

  private val SESSION_CHANNEL_TYPE = "session"

  private val senderChannel = ChannelPacket.increaseSenderChannal()
  private var recipientChannel: Int = _
  private var initialWindowSize: Int = _
  private var maxPacketSize: Int = _

  def generateSessionChannelOpenPacket(): SSHBuffer = {
    val buffer = new SSHBuffer()
    buffer.putByte(SSH_MSG_CHANNEL_OPEN)
    buffer.putString(SESSION_CHANNEL_TYPE)
    buffer.putInt(senderChannel)
    buffer.putInt(65536) // 64KB
    buffer.putInt(32768) // 32kB
    buffer.encryptAndAppendMAC()
  }

  def receiveChannelOpenConfirmation(in: InputStream): Unit = {
    val reader = new SSHEncryptedStreamBufferReader(in)
    val payloadBuffer = reader.reader
    val paddingLength = payloadBuffer.getByte()
    val cmd = payloadBuffer.getByte()
    if (cmd != SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
      throw new Exception(s"Unexpected cmd $cmd, expect $SSH_MSG_CHANNEL_OPEN_CONFIRMATION")
    }
    recipientChannel = payloadBuffer.getInt()
    val senderChannel = payloadBuffer.getInt()
    initialWindowSize = payloadBuffer.getInt()
    maxPacketSize = payloadBuffer.getInt()

    println(s"  recipientChannel = $recipientChannel")
    println(s"  senderChannel = $senderChannel")
    println(s"  initialWindowSize = $initialWindowSize")
    println(s"  maxPacketSize = $maxPacketSize")
  }

  def generateChannelRequest(cmd: String): SSHBuffer = {
    val buffer = new SSHBuffer()
    buffer.putByte(SSH_MSG_CHANNEL_REQUEST)
    buffer.putInt(recipientChannel)
    buffer.putString("exec")
    buffer.putByte(1) // want reply
    buffer.putString(cmd)
    buffer.encryptAndAppendMAC()
  }

  def receiveChannelSuccess(in: InputStream): Unit = {
    val reader = new SSHEncryptedStreamBufferReader(in)
    val payloadBuffer = reader.reader
    val paddingLength = payloadBuffer.getByte()
    val cmd = payloadBuffer.getByte()
    if (cmd != SSH_MSG_CHANNEL_SUCCESS) {
      throw new Exception(s"Unexpected cmd $cmd, expect $SSH_MSG_CHANNEL_SUCCESS")
    }
    val currentRecipientChannel = payloadBuffer.getInt()
    println(s"  currentRecipientChannel = $currentRecipientChannel")
  }

  def receiveData(in: InputStream): Unit = {
    val reader = new SSHEncryptedStreamBufferReader(in)
    val payloadBuffer = reader.reader
    val paddingLength = payloadBuffer.getByte()
    val cmd = payloadBuffer.getByte()
    if (cmd != SSH_MSG_CHANNEL_DATA) {
      throw new Exception(s"Unexpected cmd $cmd, expect $SSH_MSG_CHANNEL_DATA")
    }
    val currentRecipientChannel = payloadBuffer.getInt()
    println(s"  currentRecipientChannel = $currentRecipientChannel")
    val data = payloadBuffer.getString()
    println(s"  response: $data")
  }

  def generateCloseChannelPacket(): SSHBuffer = {
    val buffer = new SSHBuffer()
    buffer.putByte(SSH_MSG_CHANNEL_CLOSE)
    buffer.putInt(recipientChannel)
    buffer.encryptAndAppendMAC()
  }

  def receiveCloseChannel(in: InputStream): Unit = {
    val reader = new SSHEncryptedStreamBufferReader(in)
    val payloadBuffer = reader.reader
    val paddingLength = payloadBuffer.getByte()
    val cmd = payloadBuffer.getByte()
    if (cmd != SSH_MSG_CHANNEL_CLOSE) {
      throw new Exception(s"Unexpected cmd $cmd, expect $SSH_MSG_CHANNEL_CLOSE")
    }
    val currentRecipientChannel = payloadBuffer.getInt()
    println(s"  currentRecipientChannel = $currentRecipientChannel")
  }
}

object ChannelPacket {
  private var senderChannel = -1

  def increaseSenderChannal(): Int = {
    senderChannel += 1
    senderChannel
  }
}
