package me.ihainan.algorithms

import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}
import me.ihainan.SSHSession
import me.ihainan.utils.SSHFormatter

// https://github.com/rtyley/jsch/blob/master/src/com/jcraft/jsch/jce/AES256CTR.java
class AES256CTR(mode: Int, key: Array[Byte], iv: Array[Byte]) {
  private val ivSize = 16
  private val bSize = 32
  private var cipher: Cipher = _

  val pad = "NoPadding"
  var tmpIv = iv
  var tmpKey = key

  if (iv.length > ivSize) {
    tmpIv = new Array[Byte](ivSize)
    System.arraycopy(iv, 0, tmpIv, 0, ivSize)
  }

  if (key.length > bSize) {
    tmpKey = new Array[Byte](bSize)
    System.arraycopy(key, 0, tmpKey, 0, bSize)
  }

  try {
    val keySpec = new SecretKeySpec(tmpKey, "AES")
    cipher = Cipher.getInstance(s"AES/CTR/$pad")
    cipher.init(
      if (mode == Cipher.ENCRYPT_MODE) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE,
      keySpec,
      new IvParameterSpec(tmpIv)
    )
  } catch {
    case e: Exception =>
      cipher = null
      throw e
  }

  def update(input: Array[Byte],
             inputOffset: Int,
             inputLen: Int,
             output: Array[Byte],
             outputOffset: Int): Unit = {
    cipher.update(input, inputOffset, inputLen, output, outputOffset)
  }
}

object AES256CTR {
  def encrypt(plainText: Array[Byte]): Array[Byte] = {
    println(" Plain text: " + SSHFormatter.formatByteArray(plainText))
    val cipherText = new Array[Byte](plainText.length)
    SSHSession.getAESEncrypt.update(plainText, 0, plainText.length, cipherText, 0)
    println(" Encrypted text: " + SSHFormatter.formatByteArray(cipherText))
    cipherText
  }

  def decrypt(cipherText: Array[Byte]): Array[Byte] = {
    val decryptedText = new Array[Byte](cipherText.length)
    SSHSession.getAESDecrypt.update(cipherText, 0, cipherText.length, decryptedText, 0)
    decryptedText
  }
}