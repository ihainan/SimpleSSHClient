package me.ihainan

import me.ihainan.utils.SSHBuffer
import me.ihainan.utils.SSHFormatter

object Test extends App {
  def hexToBytes(hex: String): Array[Byte] = {
    require(hex.length % 2 == 0, "Hex string must have an even length")

    hex.sliding(2, 2).toArray.map { byteStr =>
      Integer.parseInt(byteStr, 16).toByte
    }
  }

  val hexString = "000004440a1f00000197000000077373682d727361000000030100010000018100e26876f146b1261482fc283f53b8b20cf33e834637f416f71793f016236fa8017b96238760aeb2b7c7df80a9341ef94ea61a1c8ba859ead3cec322b9a823020fb51a4038890538efd58297636cdfb3a83d35ce9c1a16dfb99bf1d7a7cb00ba1218c292950168a6c5e9e0df7cb31512e2ef41c782197394b077a4829de02c7ac37029d19f82c66e165f311e3f28e5cd4ded0d1ea16ecf0b5de28c59940ad8d48963e67c4446928188f696d4ff966584b3b86298cc3558607cff3151f7eb592def96f12ab562fa6a5a293a9d3087eaee82956a3ea38db2a6668f0b2188dc075c49127abc9de74a060b31ec1f9bbc2188e20b64af95651c61f8342e4771129c38a229211a782217bedd58503e82f07eef1828ee404447000a66435bcf1733f916d7e16d0726eca6764e6e1e86c5660eff956d0a92d25c6e27b62edc74e593101be7cdb9901995a9956b521e25c431f08d78d868bec92836333471937b6d4edb7d1c06bc622052d64267e04bc785835818ff5f0af9d3b63f259e3ea9adacfc696e1d0000010100cece862c1dd21eaed273b566b97be4938d668ce431390299a9bedb25bf5ace6b67d55c76b37a3af5d5ec454383ef16270c081fbbffdbf2860448714d0f1ac1790f0830e1fdb68f6004384afbf8041d0bb41dc1ed16f461920a8bc8b02c3f95792f9ec1c81c6f66bf848cf30d37dc185a5fc659455fba233eeb0b0a70265d8d858d96a516f33b23ec25b19233bd0cda0ceb2c493c2dd168e72879382c5c650570a5272045509cf278f64bc997d76a07136c898cf84ed6238987280287ae0ca71e7a88a4df9fe14e8c85d809f120fb696e60083deaa098f26b4274a4599acde05f7148e3fb98d5ef6593810a2852f2bef7bafe987d92025a59a85d27cbf47a9f33000001940000000c7273612d736861322d3531320000018058dc3fd8a910bc909e10c63bb468b3d8cb7a45ce8076cf415c37e7587646e55efb1114b938341470aa5cbf2203331e532e59badfed65ece6fc764c29cb2918fe5d2b941bffbacd468adecbfc709a294b98d9077c323459e0da37e50144dfc7100f94219b95a9362c8b68615f090227b51fcad52af1d3e6f758452de85ff3dad9ae8b2c60ae80c411dce3cce5f4c97477d36efdb2e8849fa747e6ac98bacc4459df7c8612a743b057c536a25a7817912ded78317629f35661ffb520c7b76c7b41f8f816dccaa2a13ebb3224687e160c42588abcc2352eb2239f5c15669e170c4588f025d78fdd4ab89866fe84ca7aa863ba3dce46bf0d628837a5647dfb220fd32342c5d025dcc29650e8473cef054a23cf2645fa8edb148ebfad10af1af061f6cb9895b1ebadbb5099c639d3730a219183bdd7543e7a1a615ac50ea8c259cf3fa430f33a2eacec9db6b57d89dc2f3f430bc5adf2dc92de0abd91e351cb345d527eb2b167847961c782bdeae6a8b33896edf2a71620968afff3b0186ca18a2c2800000000000000000000"
  val byteArray = hexToBytes(hexString)

  println(SSHFormatter.encodeToBase64(byteArray))
}
