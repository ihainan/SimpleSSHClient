package me.ihainan

import java.math.BigInteger
import me.ihainan.algorithms.DHKeyExchangeAlgorithm
import java.security.interfaces.RSAPublicKey
import scala.util.control.Exception.By

object SSHSession {
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

}
