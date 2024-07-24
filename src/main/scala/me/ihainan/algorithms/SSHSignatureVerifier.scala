package me.ihainan.algorithms

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security._

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security._

object SSHSignatureVerifier {

  def verifySignature(
      clientVersion: String,
      serverVersion: String,
      clientKexInit: Array[Byte],
      serverKexInit: Array[Byte],
      serverHostKey: PublicKey,
      e: BigInteger,
      f: BigInteger,
      k: BigInteger,
      signature: Array[Byte]): Boolean = {

    // 1. 构建要签名的数据
    val dataToSign = buildDataToSign(clientVersion, serverVersion, clientKexInit,
      serverKexInit, serverHostKey, e, f, k)

    // 2. 计算哈希
    val sha256 = MessageDigest.getInstance("SHA-256")
    val hash = sha256.digest(dataToSign)

    // 3. 验证签名
    val sig = Signature.getInstance("SHA256withRSA")
    sig.initVerify(serverHostKey)
    sig.update(hash)

    sig.verify(signature)
  }

  private def buildDataToSign(
      clientVersion: String,
      serverVersion: String,
      clientKexInit: Array[Byte],
      serverKexInit: Array[Byte],
      serverHostKey: PublicKey,
      e: BigInteger,
      f: BigInteger,
      k: BigInteger): Array[Byte] = {

    val baos = new ByteArrayOutputStream()
    try {
      // 按照SSH协议规定的顺序写入数据
      baos.write(clientVersion.getBytes(StandardCharsets.UTF_8))
      baos.write(serverVersion.getBytes(StandardCharsets.UTF_8))
      writeString(baos, clientKexInit)
      writeString(baos, serverKexInit)
      writeString(baos, serverHostKey.getEncoded)
      writeMPInt(baos, e)
      writeMPInt(baos, f)
      writeMPInt(baos, k)

      baos.toByteArray
    } finally {
      baos.close()
    }
  }

  private def writeString(baos: ByteArrayOutputStream, str: Array[Byte]): Unit = {
    baos.write((str.length >>> 24) & 0xff)
    baos.write((str.length >>> 16) & 0xff)
    baos.write((str.length >>> 8) & 0xff)
    baos.write(str.length & 0xff)
    baos.write(str)
  }

  private def writeMPInt(baos: ByteArrayOutputStream, bi: BigInteger): Unit = {
    val bytes = bi.toByteArray
    if ((bytes(0) & 0x80) != 0) {
      baos.write(0)
    }
    writeString(baos, bytes)
  }

  def main(args: Array[String]): Unit = {
    try {
      // 这里需要填入实际的值
      val clientVersion = "SSH-2.0-OpenSSH_8.1"
      val serverVersion = "SSH-2.0-OpenSSH_7.4"
      val clientKexInit: Array[Byte] = ??? // 客户端的 KEXINIT 消息
      val serverKexInit: Array[Byte] = ??? // 服务器的 KEXINIT 消息
      val serverHostKey: PublicKey = ??? // 服务器的公钥
      val e: BigInteger = ??? // 客户端的 DH 公钥
      val f: BigInteger = ??? // 服务器的 DH 公钥
      val k: BigInteger = ??? // 共享密钥
      val signature: Array[Byte] = ??? // 服务器的签名

      val isValid = verifySignature(clientVersion, serverVersion, clientKexInit,
        serverKexInit, serverHostKey, e, f, k, signature)

      println(s"Signature is valid: $isValid")
    } catch {
      case e: Exception => e.printStackTrace()
    }
  }
}
