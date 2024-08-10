package me.ihainan.utils

import org.apache.commons.codec.binary.Hex
import java.util.Base64

object SSHFormatter {
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
    sb.toString.trim()
  }

  def encodeToBase64(bytes: Array[Byte]): String = {
    Base64.getEncoder().encodeToString(bytes)
  }
}
