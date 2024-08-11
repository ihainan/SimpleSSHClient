package me.ihainan.packets

import java.lang
import java.io.InputStream
import java.nio.ByteBuffer
import me.ihainan.utils.SSHBuffer
import me.ihainan.utils.SSHStreamBufferReader
import me.ihainan.utils.SSHBufferReader
import java.math.BigInteger
import me.ihainan.SSHSession
import me.ihainan.algorithms.RSAAlgorithm
import me.ihainan.algorithms.SSHSignatureVerifier
import me.ihainan.algorithms.AES256CTR.logger
import org.slf4j.LoggerFactory

// https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
// https://datatracker.ietf.org/doc/html/rfc4253#section-8.2
object DiffieHellmanGroup14Packet {
  private val logger = LoggerFactory.getLogger(getClass().getName())
  
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
    val streamReader = new SSHStreamBufferReader(in)
    val reader = streamReader.reader
    val packetLength = streamReader.packetLength
    val paddingLength = reader.getByte()
    val payloadBytes = reader.getByteArray(packetLength - paddingLength - 1)
    val payloadReader = new SSHBufferReader(payloadBytes)

    // read payload
    val command = payloadReader.getByte() // SSH_MSG_KEXDH_REPLY
    logger.debug(s"  packet command = $command")

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
    logger.debug("  Server's RSA public key: " + RSAAlgorithm.convertToOpenSSHFormat(serverRSAPublicKey))

    // Save into SSHSession
    SSHSession.setF(serverDHF)
    SSHSession.setKS(ks)

    // validate the signature
    SSHSignatureVerifier.verifySignature(signatureBytes)

    // derive keys and initialize ciphers
    SSHSession.derivateKeys()
  }
}
