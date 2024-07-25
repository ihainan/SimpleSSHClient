package me.ihainan.utils

import java.nio.ByteBuffer
import java.io.InputStream
import java.math.BigInteger

// https://github.com/mwiede/jsch/blob/master/src/main/java/com/jcraft/jsch/Buffer.java
class SSHBuffer {
  private val buffer = collection.mutable.ArrayBuffer.empty[Byte]

  def putString(str: String): Unit = {
    putInt(str.length())
    putByteArray(str.getBytes())
  }

  def putInt(num: Int): Unit = {
    putByteArray(
      Array(
        ((num >> 24) & 0xff).toByte,
        ((num >> 16) & 0xff).toByte,
        ((num >> 8) & 0xff).toByte,
        (num & 0xff).toByte
      ))
  }

  def putByte(num: Byte): Unit = {
    buffer += num
  }

  def putByteArray(bytes: Array[Byte]): Unit = {
    buffer.appendAll(bytes)
  }

  def putByteArrayWithLength(bytes: Array[Byte]): Unit = {
    putInt(bytes.length)
    buffer.appendAll(bytes)
  }

  def putMPInt(bytes: Array[Byte]): Unit = {
    val len = bytes.length
    if ((bytes.head & 0x80) != 0) {
      // to avoid negative value
      putInt(len + 1)
      putByte(0.toByte)
    } else {
      putInt(len)
    }
    putByteArray(bytes)
  }

  def putMPInt(num: BigInteger): Unit = {
    putMPInt(num.toByteArray())
  }

  def length: Int = buffer.length

  def getData = buffer.toArray

  private def calculatePaddingLength(payloadLength: Int, blockSize: Int = 8): Int = {
    // initial length = 4 (packet_length) + 1 (padding_length) + payload_length
    val initialLength = 4 + 1 + payloadLength
    val paddingLength = blockSize - (initialLength % blockSize)

    // padding length must be at least 4 bytes
    if (paddingLength < 4) {
      paddingLength + blockSize
    } else {
      paddingLength
    }
  }

  def wrapWithPadding(): SSHBuffer = {
    val bytes = getData
    val newBuffer = new SSHBuffer()
    val paddingLength = calculatePaddingLength(bytes.length)
    val packetLength = bytes.length + paddingLength + 1
    newBuffer.putInt(packetLength)
    newBuffer.putByte(paddingLength.toByte)
    newBuffer.putByteArray(bytes)
    (0 until paddingLength).foreach(_ => newBuffer.putByte(0.toByte))
    newBuffer
  }
}

class SSHStreamBufferReader(in: InputStream) {
  private def readInt(in: InputStream): Int = {
    val bytes = new Array[Byte](4)
    val bytesRead = in.read(bytes)
    if (bytesRead != 4) {
      throw new IllegalStateException(
        "Could not read 4 bytes from the InputStream"
      )
    }
    ByteBuffer.wrap(bytes).getInt
  }

  private def readByteArray(in: InputStream, length: Int): Array[Byte] = {
    val bytes = new Array[Byte](length)
    val bytesRead = in.read(bytes)
    if (bytesRead != length) {
      throw new IllegalStateException(
        s"Could not read $length bytes from the InputStream"
      )
    }
    bytes
  }

  val _buffer = new SSHBuffer()
  val _packetLength = readInt(in)
  val data = readByteArray(in, packetLength)
  _buffer.putByteArray(data)

  def reader = new SSHBufferReader(_buffer.getData)

  def packetLength = _packetLength
}

class SSHBufferReader(buffer: Array[Byte]) {
  var index = 0

  def getData() = buffer.toArray

  def getByte(): Byte = {
    val num = buffer(index)
    index += 1
    num
  }

  def getByteArray(): Array[Byte] = {
    val len = getInt()
    getByteArray(len)
  }

  def getByteArray(len: Int): Array[Byte] = {
    val bytes = (0 until len).map(_ => getByte()).toArray
    bytes
  }

  def getString(): String = {
    var len = getInt()
    if (len < 0 || len > 256 * 1024) {
      len = 256 * 1024
    }
    new String(getByteArray(len))
  }

  def getInt(): Int = {
    val bytes = (0 until 4).map(_ => getByte()).toArray
    ByteBuffer.wrap(bytes).getInt
  }

  def getMPInt(): Array[Byte] = {
    var len = getInt()
    // len < 0 means that the first byte is 1
    if (len < 0 || len > 8 * 1024) {
      len = 8 * 1024
    }
    getByteArray(len)
  }

  def getMPIntBits(): Array[Byte] = {
    val bits = getInt()
    val bytes = getByteArray((bits + 7) / 8)
    if ((bytes.head & 0x80) != 0) {
      // the first byte is 1, we don't allow negative integer so an additional 0 will be added.
      val newBytes = new Array[Byte](bytes.length + 1)
      newBytes(0) = 0.toByte
      System.arraycopy(bytes, 0, newBytes, 1, newBytes.length)
      newBytes
    } else {
      bytes
    }
  }
}

object SSHBufferUtils {}
