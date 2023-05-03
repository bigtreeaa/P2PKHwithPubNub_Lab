package com.gruut.p2pkhwithpubnub

import kotlin.random.Random
import org.bitcoinj.core.Sha256Hash.hash

class GenCoinBase {
    public fun genCoinBase(address : String, gruut : Int, hashed_pubkey : String) : String {
        val txid = hash((Random.nextBits(256)).toString().toByteArray())
        val message : String = """{"coin_base" : [
            |{
            |   "address" : $address,
            |   "gruut" : $gruut,
            |   "script_code" : "76a914${hashed_pubkey}88ac"
            |}]}
        """.trimMargin()
        return message
    }

}