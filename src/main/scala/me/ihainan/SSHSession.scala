package me.ihainan

import java.math.BigInteger
import me.ihainan.algorithms.DHKeyExchangeAlgorithm
import java.security.interfaces.RSAPublicKey

object SSHSession {
  private var _clientVersion: String = _
  private var _serverVersion: String = _
  private var _IC: Array[Byte] = _
  private var _IS: Array[Byte] = _
  // private var _e: BigInteger = _
  private var _f: BigInteger = _

  def setClientVersion(clientVersion: String): Unit = {
    this._clientVersion = clientVersion
  }

  def getClientVersion = _clientVersion

  def setServerVersion(serverVerson: String): Unit = {
    this._serverVersion = serverVerson
  }

  def getServerVersion = _serverVersion

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

  def setF(f: BigInteger): Unit = {
    _f = f
    this.keyExchangeAlgorithm.setServerDHPublicKey(f.toByteArray())
    this.keyExchangeAlgorithm.generateSharedSecret()
  }

  def getF(): BigInteger = _f

  // algorithm & keys
  private var _serverRSAPublicKey: RSAPublicKey = _
  val keyExchangeAlgorithm = new DHKeyExchangeAlgorithm()


  def setServerRSAPublicKey(key: RSAPublicKey): Unit = {
    _serverRSAPublicKey = key
  }

  def getServerRSAPublicKey(): RSAPublicKey = _serverRSAPublicKey

}
