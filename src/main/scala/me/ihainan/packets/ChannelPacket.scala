package me.ihainan.packets

import me.ihainan.utils.SSHBuffer
import me.ihainan.utils.SSHEncryptedStreamBufferReader
import java.io.InputStream
import scala.io.StdIn
import java.io.OutputStream
import org.slf4j.LoggerFactory

// https://www.rfc-editor.org/rfc/rfc4254
class ChannelPacket(in: InputStream, out: OutputStream) {
  private val logger = LoggerFactory.getLogger(getClass().getName())

  private val SSH_MSG_GLOBAL_REQUEST = 80.toByte
  private val SSH_MSG_REQUEST_SUCCESS = 81.toByte
  private val SSH_MSG_REQUEST_FAILURE = 82.toByte
  private val SSH_MSG_CHANNEL_OPEN = 90.toByte
  private val SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91.toByte
  private val SSH_MSG_CHANNEL_OPEN_FAILURE = 92.toByte
  private val SSH_MSG_CHANNEL_WINDOW_ADJUST = 93.toByte
  private val SSH_MSG_CHANNEL_DATA = 94.toByte
  private val SSH_MSG_CHANNEL_EXTENDED_DATA = 95.toByte
  private val SSH_MSG_CHANNEL_EOF = 96.toByte
  private val SSH_MSG_CHANNEL_CLOSE = 97.toByte
  private val SSH_MSG_CHANNEL_REQUEST = 98.toByte
  private val SSH_MSG_CHANNEL_SUCCESS = 99.toByte
  private val SSH_MSG_CHANNEL_FAILURE = 100.toByte

  private val codeMap = Map(
    80.toByte -> "SSH_MSG_GLOBAL_REQUEST",
    81.toByte -> "SSH_MSG_REQUEST_SUCCESS",
    82.toByte -> "SSH_MSG_REQUEST_FAILURE",
    90.toByte -> "SSH_MSG_CHANNEL_OPEN",
    91.toByte -> "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
    92.toByte -> "SSH_MSG_CHANNEL_OPEN_FAILURE",
    93.toByte -> "SSH_MSG_CHANNEL_WINDOW_ADJUST",
    94.toByte -> "SSH_MSG_CHANNEL_DATA",
    95.toByte -> "SSH_MSG_CHANNEL_EXTENDED_DATA",
    96.toByte -> "SSH_MSG_CHANNEL_EOF",
    97.toByte -> "SSH_MSG_CHANNEL_CLOSE",
    98.toByte -> "SSH_MSG_CHANNEL_REQUEST",
    99.toByte -> "SSH_MSG_CHANNEL_SUCCESS",
    100.toByte -> "SSH_MSG_CHANNEL_FAILURE"
  )

  private val SESSION_CHANNEL_TYPE = "session"

  private val senderChannel = ChannelPacket.increaseSenderChannal()
  private var recipientChannel: Int = _
  private var initialWindowSize: Int = _
  private var maxPacketSize: Int = _

  def serverListenerThread() = new Thread() {
    private val logger = LoggerFactory.getLogger(getClass().getName())

    override def run(): Unit = {
      out.write(generateSessionChannelOpenPacket.getData)
      out.flush()
      var loop = true
      while (loop) {
        val reader = new SSHEncryptedStreamBufferReader(in)
        val payloadBuffer = reader.reader
        val paddingLength = payloadBuffer.getByte()
        val cmd = payloadBuffer.getByte()
        logger.info(s"Received " + codeMap(cmd))
        cmd match {
          case SSH_MSG_GLOBAL_REQUEST =>
          case SSH_MSG_REQUEST_SUCCESS =>
          case SSH_MSG_REQUEST_FAILURE =>
          case SSH_MSG_CHANNEL_OPEN =>
          case SSH_MSG_CHANNEL_OPEN_CONFIRMATION =>
            recipientChannel = payloadBuffer.getInt()
            val senderChannel = payloadBuffer.getInt()
            initialWindowSize = payloadBuffer.getInt()
            maxPacketSize = payloadBuffer.getInt()
            logger.debug("  recipientChannel = {}", recipientChannel)
            logger.debug("  initialWindowSize = {}", initialWindowSize)
            logger.debug("  maxPacketSize = {}", maxPacketSize)

            // read user's input
            print("> ")
            val cmd = StdIn.readLine()
            out.write(generateChannelRequest(cmd).getData)
            out.flush
          case SSH_MSG_CHANNEL_OPEN_FAILURE =>
            throw new Exception("Failed to open a channel")
          case SSH_MSG_CHANNEL_WINDOW_ADJUST =>
          case SSH_MSG_CHANNEL_DATA =>
            val currentRecipientChannel = payloadBuffer.getInt()
            val data = payloadBuffer.getString()
            println(data)
          case SSH_MSG_CHANNEL_EXTENDED_DATA =>
            val currentRecipientChannel = payloadBuffer.getInt()
            val dataType = payloadBuffer.getInt()
            logger.debug("  currentRecipientChannel = {}", currentRecipientChannel)
            logger.debug("  dataType = {}", dataType)
            val data = payloadBuffer.getString()
            System.err.println(data)
          case SSH_MSG_CHANNEL_EOF =>
            logger.info("Channel closing...")
            out.write(generateCloseChannelPacket().getData)
            out.flush
          case SSH_MSG_CHANNEL_CLOSE =>
            logger.info("Channel closed.")
            loop = false
          case SSH_MSG_CHANNEL_REQUEST =>
          case SSH_MSG_CHANNEL_SUCCESS =>
            val currentRecipientChannel = payloadBuffer.getInt()
            logger.info("  Channel opened, recipient channel is {}", currentRecipientChannel)
          case SSH_MSG_CHANNEL_FAILURE =>
            System.err.println("Failed to open channel")
            println("BYE!")
            loop = false
        }
      }
    }
  }

  def generateSessionChannelOpenPacket(): SSHBuffer = {
    val buffer = new SSHBuffer()
    buffer.putByte(SSH_MSG_CHANNEL_OPEN)
    buffer.putString(SESSION_CHANNEL_TYPE)
    buffer.putInt(senderChannel)
    buffer.putInt(65536) // 64KB
    buffer.putInt(32768) // 32kB
    buffer.encryptAndAppendMAC()
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

  def generateCloseChannelPacket(): SSHBuffer = {
    val buffer = new SSHBuffer()
    buffer.putByte(SSH_MSG_CHANNEL_CLOSE)
    buffer.putInt(recipientChannel)
    buffer.encryptAndAppendMAC()
  }
}

object ChannelPacket {
  private var senderChannel = -1

  def increaseSenderChannal(): Int = {
    senderChannel += 1
    senderChannel
  }
}
