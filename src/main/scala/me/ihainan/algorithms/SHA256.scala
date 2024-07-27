package me.ihainan.algorithms

import java.security.MessageDigest

object SHA256 {
  def computHash(data: Array[Byte]): Array[Byte] = {
    val sha256 = MessageDigest.getInstance("SHA-256")
    sha256.update(data)
    sha256.digest()
  }
}
