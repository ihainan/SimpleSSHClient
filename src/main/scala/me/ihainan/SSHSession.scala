package me.ihainan

import java.math.BigInteger
import me.ihainan.algorithms.DHKeyExchangeAlgorithm
import java.security.interfaces.RSAPublicKey
import scala.util.control.Exception.By
import me.ihainan.utils.SSHBuffer
import me.ihainan.algorithms.AES256CTR
import javax.crypto.Cipher
import me.ihainan.algorithms.HMACSHA1
import me.ihainan.algorithms.SHA256
import me.ihainan.utils.SSHFormatter

object SSHSession {
  // Sequence numbers
  private var _clientSeqNum = 0
  private var _serverSeqNum = 0

  def addClientSeqNum(): Unit = {
    _clientSeqNum += 1
  }

  def addServerSeqNum(): Unit = {
    _serverSeqNum += 1
  }

  def getClientSeqNum(): Int = _clientSeqNum

  def getServerSeqNum(): Int = _serverSeqNum

  // H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
  private var _clientVersion: String = _
  private var _serverVersion: String = _
  // The payload of the client's SSH_MSG_KEXINIT: 0x14, ..., reversed
  private var _IC: Array[Byte] = _
  // The payload of the server's SSH_MSG_KEXINIT: 0x14, ..., reversed
  private var _IS: Array[Byte] = _
  // the server's KEX host key part without the length information
  private var _KS: Array[Byte] = _
  // DH client e
  def getE(): BigInteger = keyExchangeAlgorithm.clientE
  // DH server f
  private var _f: Array[Byte] = _
  // Shared key
  def getK(): Array[Byte] = keyExchangeAlgorithm.sharedSecret
  // Exchanged hash
  private var _H: Array[Byte] = _
  // Session ID, we assume that the key exchange only happens once, the session ID = H
  def getSessionID: Array[Byte] = getH()

  def setH(h: Array[Byte]): Unit = {
    _H = h.toArray
  }

  def getH(): Array[Byte] = _H.toArray

  def setClientVersion(clientVersion: String): Unit = {
    this._clientVersion = clientVersion
  }

  def getClientVersion = _clientVersion

  def setServerVersion(serverVerson: String): Unit = {
    this._serverVersion = serverVerson
  }

  def getServerVersion = _serverVersion

  def setKS(ks: Array[Byte]): Unit = {
    _KS = ks
  }

  def getKS(): Array[Byte] = {
    _KS.toArray
  }

  def setIC(ic: Array[Byte]): Unit = {
    _IC = ic.toArray
  }

  def getIC(): Array[Byte] = {
    _IC.toArray
  }

  def setIS(is: Array[Byte]): Unit = {
    _IS = is
  }

  def getIS(): Array[Byte] = {
    _IS.toArray
  }

  // def setE(e: BigInteger): Unit = {
  //   _e = e
  // }

  // def getE(): BigInteger = _e

  def setF(f: Array[Byte]): Unit = {
    _f = f
    this.keyExchangeAlgorithm.setServerDHPublicKey(f)
    this.keyExchangeAlgorithm.generateSharedSecret()
  }

  def getF(): Array[Byte] = _f

  // algorithm & keys
  private var _serverRSAPublicKey: RSAPublicKey = _
  val keyExchangeAlgorithm = new DHKeyExchangeAlgorithm()

  def setServerRSAPublicKey(key: RSAPublicKey): Unit = {
    _serverRSAPublicKey = key
  }

  def getServerRSAPublicKey(): RSAPublicKey = _serverRSAPublicKey

  /********************* Key Derivation ***************************/
  // https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
  private def derivateKey(c: Char): Array[Byte] = {
    val buffer = new SSHBuffer()
    buffer.putMPInt(SSHSession.getK())
    buffer.putByteArray(SSHSession.getH())
    buffer.putByte(c.toByte)
    buffer.putByteArray(SSHSession.getSessionID)
    SHA256.computHash(buffer.getData).toArray
  }

  private var _IVc2s: Array[Byte] = _
  private var _IVs2c: Array[Byte] = _
  private var _Kc2s: Array[Byte] = _
  private var _Ks2c: Array[Byte] = _
  private var _MACKc2s: Array[Byte] = _
  private var _MACKs2c: Array[Byte] = _

  private var _aesEncrypt: AES256CTR = _
  private var _aesDecrypt: AES256CTR = _
  private var _hmacClientToServer: HMACSHA1 = _
  private var _hmacServerToClient: HMACSHA1 = _

  def getAESEncrypt() = _aesEncrypt

  def getAESDecrypt() = _aesDecrypt

  def getHMACClientToServer() = _hmacClientToServer

  def getHMACServerToClient() = _hmacServerToClient

  // https://github.com/apache/mina-sshd/blob/4b30ab065d065a9b85a8b5f65df0d6ad111fae3c/sshd-core/src/main/java/org/apache/sshd/common/session/helpers/AbstractSession.java#L1915
  def derivateKeys(): Unit = {
    println("Derivating keys...")
    _IVc2s = derivateKey('A')
    _IVs2c = derivateKey('B')
    _Kc2s = derivateKey('C')
    _Ks2c = derivateKey('D')
    _MACKc2s = derivateKey('E')
    _MACKs2c = derivateKey('F')

    println("  _IVc2s: " + SSHFormatter.formatByteArray(_IVc2s))
    println("  _IVs2c: " + SSHFormatter.formatByteArray(_IVs2c))
    println("  _Kc2s: " + SSHFormatter.formatByteArray(_Kc2s))
    println("  _Ks2c: " + SSHFormatter.formatByteArray(_Ks2c))
    println("  _MACKc2s: " + SSHFormatter.formatByteArray(_MACKc2s))
    println("  _MACKs2c: " + SSHFormatter.formatByteArray(_MACKs2c))

    _aesEncrypt = new AES256CTR(Cipher.ENCRYPT_MODE, _Kc2s, _IVc2s)
    _aesDecrypt = new AES256CTR(Cipher.DECRYPT_MODE, _Ks2c, _IVs2c)

    _hmacClientToServer = new HMACSHA1(_MACKc2s)
    _hmacServerToClient = new HMACSHA1(_MACKs2c)
  }

  // def getIVc2s() = _IVc2s.toArray

  // def getKcc2s() = _Kc2s.toArray

  // def getMACKc2s() = _MACKc2s.toArray

}
