package me.ihainan.packets

import java.lang
import java.io.InputStream
import java.nio.ByteBuffer
import me.ihainan.utils.SSHBuffer
import me.ihainan.utils.SSHStreamBufferReader
import me.ihainan.utils.SSHBufferReader
import com.ibm.j9ddr.vm29.pointer.generated.messagePointer
import java.math.BigInteger
import me.ihainan.SSHSession
import me.ihainan.algorithms.RSAAlgorithm
import me.ihainan.algorithms.SSHSignatureVerifier

object DiffieHellmanGroup14Packet {
  private val DH_EXCHANGE_CODE = 0x1e.toByte

  private def generatePayload(): SSHBuffer = {
    val buffer = new SSHBuffer()
    buffer.putByte(DH_EXCHANGE_CODE)
    val clientE = SSHSession.keyExchangeAlgorithm.clientE
    buffer.putMPInt(clientE)
    buffer
  }

  def generateDHInitPacket(): SSHBuffer = {
    val payloadBuffer = generatePayload()
    val buffer = payloadBuffer.wrapWithPadding()
    buffer
  }

  def readServerPublibKeyFromInputStream(in: InputStream): Unit = {
    // REF: https://www.rfc-editor.org/rfc/rfc4253#page-22

    // parse packet
    val streamReader = new SSHStreamBufferReader(in)
    val reader = streamReader.reader
    val packetLength = streamReader.packetLength
    val paddingLength = reader.getByte()
    val payloadBytes = reader.getByteArray(packetLength - paddingLength - 1)
    val payloadReader = new SSHBufferReader(payloadBytes)

    // read payload
    val messageCode = payloadReader.getByte() // SSH_MSG_KEXDH_REPLY
    // println(s"  packet message code = $messageCode")

    // server public host key and certificates (K_S)
    val ks = payloadReader.getByteArray()
    val hostKeyReader = new SSHBufferReader(ks)
    val hostKeyType = hostKeyReader.getString()
    val serverRSAE = new BigInteger(hostKeyReader.getMPInt())
    val serverRSAN = new BigInteger(hostKeyReader.getMPInt())

    // f
    val serverDHF = payloadReader.getMPInt()

    // signature of H
    val signatureBytes = payloadReader.getByteArray()

    // Generate server's public key
    val serverRSAPublicKey = RSAAlgorithm.generateRSAPublicKey(serverRSAE, serverRSAN)
    SSHSession.setServerRSAPublicKey(serverRSAPublicKey)

    // TODO: validate server's public key
    println("  Server's RSA public key: " + RSAAlgorithm.convertToOpenSSHFormat(serverRSAPublicKey))

    // Save into SSHSession
    SSHSession.setF(serverDHF)
    SSHSession.setKS(ks)

    // validate the signature
    SSHSignatureVerifier.verifySignature(signatureBytes)
  }
}
