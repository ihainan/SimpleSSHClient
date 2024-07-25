package me.ihainan.utils

import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers._

class SSHBufferSpec extends AnyFunSuite {
  val buffer = new SSHBuffer()
  buffer.putByte(0.toByte)
  buffer.putByteArray(Array(1.toByte, 2.toByte))
  buffer.putInt(3)
  buffer.putString("Hello World")
  buffer.putMPInt(Array(4.toByte, 5.toByte))
  buffer.putMPInt(Array(128.toByte))

  test("SSHBuffer") {
    buffer.length shouldBe 34
    val bytes = buffer.getData
    println(SSHFormatter.formatByteArray(bytes))
    SSHFormatter.formatByteArray(bytes) shouldBe """00 01 02 00 00 00 03 00 00 00 0b 48 65 6c 6c 6f 20 57 6f 72 6c 64 00 00 00 02 04 05 00 00 00 02 00 80"""

  }

  test("SSHBufferReader") {
    val reader = new SSHBufferReader(buffer.getData)
    reader.getByte() shouldBe 0.toByte
    SSHFormatter.formatByteArray(reader.getByteArray(2)) shouldBe "01 02"
    reader.getInt() shouldBe 3
    reader.getString() shouldBe "Hello World"
    SSHFormatter.formatByteArray(reader.getMPInt()) shouldBe "04 05"
    SSHFormatter.formatByteArray(reader.getMPInt()) shouldBe "00 80"
  }
}
