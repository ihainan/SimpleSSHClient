package me.ihainan

import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers._
import java.io.ByteArrayInputStream
import AlgorithmNegotiationPacket._

class AlgorithmNegotiationPacketSpec extends AnyFunSuite {
  // val cookie = Array(0x6f, 0x34, 0x3a, 0xdc, 0x69, 0x15, 0x84, 0x4a, 0x9d, 0x84,
  //   0x2d, 0x36, 0x4c, 0x9c, 0xee, 0xcb).map(_.toByte)
  // val keyExchangeAlgorithms =
  //   "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c,kex-strict-c-v00@openssh.com"
  // val serverHostKeyAlgorithms =
  //   "ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256"
  // val encryptionAlgorithmsClientToServer =
  //   "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
  // val encryptionAlgorithmsServerToClient =
  //   "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
  // val macAlgorithmsClientToServer =
  //   "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
  // val macAlgorithmsServerToClient =
  //   "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
  // val compressionAlgorithmsClientToServer = "none,zlib@openssh.com,zlib"
  // val compressionAlgorithmsServerToClient = "none,zlib@openssh.com,zlib"
  // val languagesClientToServer = ""
  // val languagesServerToClient = ""
  // val firstKexPacketFollows = 0.toByte

  val exampleAlgorithmNegotiationPacket =
    new AlgorithmNegotiationPacket(
      cookie = cookie,
      keyExchangeAlgorithms = keyExchangeAlgorithms,
      serverHostKeyAlgorithms = serverHostKeyAlgorithms,
      encryptionAlgorithmsClientToServer = encryptionAlgorithmsClientToServer,
      encryptionAlgorithmsServerToClient = encryptionAlgorithmsServerToClient,
      macAlgorithmsClientToServer = macAlgorithmsClientToServer,
      macAlgorithmsServerToClient = macAlgorithmsServerToClient,
      compressionAlgorithmsClientToServer = compressionAlgorithmsClientToServer,
      compressionAlgorithmsServerToClient = compressionAlgorithmsServerToClient,
      languagesClientToServer = languagesClientToServer,
      languagesServerToClient = languagesServerToClient,
      firstKexPacketFollows = firstKexPacketFollows
    )

  test("readAlgorithmsFromInputStream should return the correct algorithms") {
    val bytes = exampleAlgorithmNegotiationPacket.toFullBytes()
    val algorithmNegotiation =
      AlgorithmNegotiationPacket.readAlgorithmsFromInputStream(
        new ByteArrayInputStream(bytes)
      )
    algorithmNegotiation.keyExchangeAlgorithms shouldBe keyExchangeAlgorithms
    algorithmNegotiation.serverHostKeyAlgorithms shouldBe serverHostKeyAlgorithms
    algorithmNegotiation.encryptionAlgorithmsClientToServer shouldBe encryptionAlgorithmsClientToServer
    algorithmNegotiation.encryptionAlgorithmsServerToClient shouldBe encryptionAlgorithmsServerToClient
    algorithmNegotiation.macAlgorithmsClientToServer shouldBe macAlgorithmsClientToServer
    algorithmNegotiation.macAlgorithmsServerToClient shouldBe macAlgorithmsServerToClient
    algorithmNegotiation.compressionAlgorithmsClientToServer shouldBe compressionAlgorithmsClientToServer
    algorithmNegotiation.compressionAlgorithmsServerToClient shouldBe compressionAlgorithmsServerToClient
    algorithmNegotiation.languagesClientToServer shouldBe languagesClientToServer
    algorithmNegotiation.firstKexPacketFollows shouldBe firstKexPacketFollows
  }
}
