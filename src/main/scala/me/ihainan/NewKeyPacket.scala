package me.ihainan

import java.io.InputStream

object NewKeyPacket {
  
  val NEW_KEY = 0x15.toByte

  def generateNewKey(): Array[Byte] = {
    val bytes = collection.mutable.ArrayBuffer.empty[Byte]
    bytes.appendAll(SSHUtils.intToBytes(12))
    bytes += 10.toByte
    bytes += NEW_KEY
    bytes.appendAll((0 until 10).map(_ => 0.toByte))
    bytes.toArray
  }

  def receiveNewKey(in: InputStream): Unit = {
    val bytes = SSHUtils.readByteArray(in, 16)
    println("  Server's new key: " + SSHUtils.formatByteArray(bytes))
  }
}
