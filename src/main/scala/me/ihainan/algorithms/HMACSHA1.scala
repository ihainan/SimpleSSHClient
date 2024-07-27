package me.ihainan.algorithms

import javax.crypto.spec.SecretKeySpec
import javax.crypto.Mac
import javax.crypto.ShortBufferException
import me.ihainan.SSHSession
import me.ihainan.utils.SSHFormatter

// https://github.com/rtyley/jsch/blob/96b0558b66ec8982e708e46b6e5a254a3650d01b/src/com/jcraft/jsch/jce/HMACSHA1.java
class HMACSHA1(key: Array[Byte]) {
  private val bsize = 20
  def getBlockSize: Int = bsize
  val tmp = new Array[Byte](4)

  val tmpKey = if (key.length > bsize) {
    val tmp = new Array[Byte](bsize)
    System.arraycopy(key, 0, tmp, 0, bsize)
    tmp
  } else {
    key
  }
  val keyspec = new SecretKeySpec(tmpKey, "HmacSHA1")
  val mac = Mac.getInstance("HmacSHA1")
  mac.init(keyspec)

  def update(i: Int): Unit = {
    tmp(0) = (i >>> 24).toByte
    tmp(1) = (i >>> 16).toByte
    tmp(2) = (i >>> 8).toByte
    tmp(3) = i.toByte
    update(tmp, 0, 4)
  }

  def update(foo: Array[Byte], s: Int, l: Int): Unit = {
    mac.update(foo, s, l)
  }

  def doFinal(buf: Array[Byte], offset: Int): Unit = {
    try {
      mac.doFinal(buf, offset)
    } catch {
      case _: ShortBufferException => // Handle the exception if needed
    }
  }
}

object HMACSHA1 {
  def generateMAC(data: Array[Byte]): Array[Byte] = {
    val hmacClientToServer = SSHSession.getHMACClientToServer()
    hmacClientToServer.update(SSHSession.getClientSeqNum())
    
    hmacClientToServer.update(data, 0, data.length)
    val macClientToServer = new Array[Byte](hmacClientToServer.getBlockSize)
    hmacClientToServer.doFinal(macClientToServer, 0)
    println("  generated MAC = " + SSHFormatter.formatByteArray(macClientToServer))
    SSHSession.addClientSeqNum()
    macClientToServer
  }

  def validateMAC(data: Array[Byte], mac: Array[Byte]): Unit = {
    val hmacVerify = SSHSession.getHMACServerToClient()
    hmacVerify.update(SSHSession.getServerSeqNum())
    SSHSession.addServerSeqNum()
    hmacVerify.update(data, 0, data.length)
    val macToVerify = new Array[Byte](hmacVerify.getBlockSize)
    hmacVerify.doFinal(macToVerify, 0)
    println("  macToVerify = " + SSHFormatter.formatByteArray(macToVerify))
    val valid = mac.sameElements(macToVerify)
    if (!valid) {
      throw new Exception("HMAC validation failed")
    }
  }
}
