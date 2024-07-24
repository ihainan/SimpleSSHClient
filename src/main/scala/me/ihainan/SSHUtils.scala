package me.ihainan

import java.io.InputStream
import java.nio.ByteBuffer
import org.apache.commons.codec.binary.Hex
import java.math.BigInteger
import java.security.PublicKey

object SSHUtils {
  def intToBytes(x: Int): Array[Byte] = {
    Array(
      ((x >> 24) & 0xff).toByte,
      ((x >> 16) & 0xff).toByte,
      ((x >> 8) & 0xff).toByte,
      (x & 0xff).toByte
    )
  }

  def bytesToHex(bytes: Array[Byte]): String = {
    bytes.map("%02x".format(_)).mkString
  }

  def appendStringWithLength(
      bytes: collection.mutable.ArrayBuffer[Byte],
      str: String
  ): Unit = {
    bytes.appendAll(SSHUtils.intToBytes(str.length))
    bytes.appendAll(str.getBytes)
  }

  def readInt(in: InputStream): Int = {
    val buffer = new Array[Byte](4)

    val bytesRead = in.read(buffer)
    if (bytesRead != 4) {
      throw new IllegalStateException(
        "Could not read 4 bytes from the InputStream"
      )
    }

    ByteBuffer.wrap(buffer).getInt
  }

  def readByteArray(in: InputStream, length: Int): Array[Byte] = {
    val buffer = new Array[Byte](length)
    val bytesRead = in.read(buffer)
    if (bytesRead != length) {
      throw new IllegalStateException(
        s"Could not read $length bytes from the InputStream"
      )
    }
    buffer
  }

  /** Format a byte array to a pretty-print hex string
    *
    * @param bytes
    *   the byte array to be formatted
    * @return
    *   pretty-print hex string
    */
  def formatByteArray(bytes: Array[Byte]): String = {
    val hexStr = Hex.encodeHexString(bytes)
    formatHexString(hexStr)
  }

  private def formatHexString(hexStr: String): String = {
    val sb = new StringBuilder()
    (0 until hexStr.length by 2).foreach { i =>
      if (i == hexStr.length - 1) {
        sb.append(hexStr(i) + " ")
      } else {
        sb.append(hexStr(i) + "" + hexStr(i + 1) + " ")
      }
    }
    sb.toString
  }

  def calculatePaddingLength(payloadLength: Int, blockSize: Int = 8): Int = {
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

  def calculatePacketLength(payloadLength: Int, paddingLength: Int): Int = {
    // packet_length = payload_length + padding_length + 1 (padding_length byte)
    payloadLength + paddingLength + 1
  }
}

class StringReader(bytes: Array[Byte]) {
  private var index = 0

  def next(): String = {
    val length = ByteBuffer.wrap(bytes.slice(index, index + 4)).getInt
    index += 4
    val str = new String(bytes.slice(index, index + length))
    index += length
    str
  }

  def getIndex: Int = index
}

case class KexHostKeInfo(algoName: String, e: BigInteger, n: BigInteger)

class KexHostKeyReader(bytes: Array[Byte]) {
  private var index = 0

  def read(): KexHostKeInfo = {
    // algorithm type, like "ssh-rsa"
    val hostKeyTypeLength = ByteBuffer.wrap(bytes.slice(0, 4)).getInt()
    index += 4
    val hostKeyType = new String(bytes.slice(index, index + hostKeyTypeLength))
    index += hostKeyTypeLength

    // mpi length for RSA public exponent e
    val eLength = ByteBuffer.wrap(bytes.slice(index, index + 4)).getInt()
    index += 4
    val e = new BigInteger(1, bytes.slice(index, index + eLength))
    index += eLength

    // mpi length for RSA modulus N
    val nLength = ByteBuffer.wrap(bytes.slice(index, index + 4)).getInt()
    index += 4
    val n = new BigInteger(1, bytes.slice(index, index + nLength))
    index += nLength

    KexHostKeInfo(algoName = hostKeyType, e = e, n = n)
  }
}
