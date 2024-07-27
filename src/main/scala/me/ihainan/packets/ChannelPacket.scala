package me.ihainan.packets

import me.ihainan.utils.SSHBuffer
import me.ihainan.utils.SSHEncryptedStreamBufferReader
import java.io.InputStream
import scala.io.StdIn
import java.io.OutputStream

// https://www.rfc-editor.org/rfc/rfc4254
class ChannelPacket(in: InputStream, out: OutputStream) {
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
    override def run(): Unit = {
      out.write(generateSessionChannelOpenPacket.getData)
      out.flush()
      while (true) {
        val reader = new SSHEncryptedStreamBufferReader(in)
        val payloadBuffer = reader.reader
        val paddingLength = payloadBuffer.getByte()
        val cmd = payloadBuffer.getByte()
        println(s"Received " + codeMap(cmd))
        cmd match {
          case SSH_MSG_GLOBAL_REQUEST =>
          case SSH_MSG_REQUEST_SUCCESS =>
          case SSH_MSG_REQUEST_FAILURE =>
          case SSH_MSG_CHANNEL_OPEN =>
          case SSH_MSG_CHANNEL_OPEN_CONFIRMATION =>
            print("> ")
            val cmd = StdIn.readLine()
            out.write(generateChannelRequest(cmd).getData)
            out.flush
          case SSH_MSG_CHANNEL_OPEN_FAILURE =>
          case SSH_MSG_CHANNEL_WINDOW_ADJUST =>
          case SSH_MSG_CHANNEL_DATA =>
            payloadBuffer.getInt()
            val data = payloadBuffer.getString()
            println(data)
          case SSH_MSG_CHANNEL_EXTENDED_DATA =>
            payloadBuffer.getInt()
            val data = payloadBuffer.getString()
            System.err.println(data)
          case SSH_MSG_CHANNEL_EOF =>
            out.write(generateCloseChannelPacket().getData)
            out.flush
          case SSH_MSG_CHANNEL_CLOSE =>
            println("BYE!")
            this.interrupt()
          case SSH_MSG_CHANNEL_REQUEST =>
          case SSH_MSG_CHANNEL_SUCCESS =>
          case SSH_MSG_CHANNEL_FAILURE =>
            System.err.println("Failed to open channel")
            println("BYE!")
            this.interrupt()
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

  def receiveChannelOpenConfirmation(in: InputStream): Unit = {
    val reader = new SSHEncryptedStreamBufferReader(in)
    val payloadBuffer = reader.reader
    val paddingLength = payloadBuffer.getByte()
    val cmd = payloadBuffer.getByte()
    if (cmd != SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
      println(s" Unexpected cmd: $cmd...will retry to read SSH_MSG_CHANNEL_OPEN_CONFIRMATION")
      receiveChannelOpenConfirmation(in)
    } else {
      if (cmd == SSH_MSG_CHANNEL_OPEN_FAILURE) {
        throw new Exception("Failed to open channel")
      } else if (cmd != SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
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
    if (cmd != SSH_MSG_CHANNEL_FAILURE && cmd != SSH_MSG_CHANNEL_SUCCESS) {
      println(s" Unexpected cmd: $cmd...will continue to wait the SSH_MSG_CHANNEL_FAILURE packet")
      receiveChannelSuccess(in)
    } else {
      if (cmd == SSH_MSG_CHANNEL_FAILURE) {
        println("  Failed to execute command, received SSH_MSG_CHANNEL_FAILURE")
      } else if (cmd != SSH_MSG_CHANNEL_SUCCESS) {
        throw new Exception(s"Unexpected cmd $cmd, expect $SSH_MSG_CHANNEL_SUCCESS")
      }
      val currentRecipientChannel = payloadBuffer.getInt()
      println(s"  currentRecipientChannel = $currentRecipientChannel")
    }
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
    println(s"  response: \n$data")
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
      println(s" Unexpected cmd: $cmd...will continue to wait the SSH_MSG_CHANNEL_CLOSE packet")
      receiveCloseChannel(in)
    } else {
      if (cmd != SSH_MSG_CHANNEL_CLOSE) {
        throw new Exception(s"Unexpected cmd $cmd, expect $SSH_MSG_CHANNEL_CLOSE")
      }
      val currentRecipientChannel = payloadBuffer.getInt()
      println(s"  currentRecipientChannel = $currentRecipientChannel")
    }
  }
}

object ChannelPacket {
  private var senderChannel = -1

  def increaseSenderChannal(): Int = {
    senderChannel += 1
    senderChannel
  }
}
