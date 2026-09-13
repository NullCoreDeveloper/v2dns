package com.v2ray.ang.fmt

import android.text.TextUtils
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.util.Utils

object VkTurnFmt : FmtBase() {
    /**
     * Parses a VK TURN URI string into a ProfileItem object.
     * Format: vkturn://<base64-encoded-JSON-config>#<remarks-url-encoded>
     * Or: freeturn://<base64url-encoded-JSON-config>
     *
     * @param str the VK TURN / FreeTURN URI string to parse
     * @return the parsed ProfileItem object, or null if parsing fails
     */
    fun parse(str: String): ProfileItem? {
        try {
            var rawUri = str.trim()
            if (rawUri.isEmpty()) return null

            // Support freeturn:// format (compatible with turn-proxy-android)
            if (rawUri.startsWith("freeturn://", ignoreCase = true)) {
                val payload = rawUri.substring(11).trim()
                val jsonStr = try {
                    val decodedBytes = android.util.Base64.decode(payload, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
                    String(decodedBytes, Charsets.UTF_8)
                } catch (e: Exception) {
                    Utils.decode(payload)
                }
                if (jsonStr.isNullOrEmpty()) return null

                val jsonObject = com.google.gson.JsonParser.parseString(jsonStr).asJsonObject
                val config = ProfileItem.create(EConfigType.VKTURN)
                val name = if (jsonObject.has("name") && !jsonObject.get("name").isJsonNull) jsonObject.get("name").asString else "FreeTURN (VK)"
                config.remarks = name.ifEmpty { "FreeTURN (VK)" }

                // Check peer ("IP:PORT")
                if (jsonObject.has("peer") && !jsonObject.get("peer").isJsonNull) {
                    val peer = jsonObject.get("peer").asString
                    val parts = peer.split(":")
                    if (parts.isNotEmpty()) config.server = parts[0]
                    if (parts.size >= 2) config.serverPort = parts[1]
                }

                // If WireGuard config text is embedded
                if (jsonObject.has("wg") && !jsonObject.get("wg").isJsonNull) {
                    val wgText = jsonObject.get("wg").asString
                    if (wgText.isNotEmpty()) {
                        val wgParsed = WireguardFmt.parseWireguardConfFile(wgText)
                        config.secretKey = wgParsed.secretKey
                        config.publicKey = wgParsed.publicKey
                        config.localAddress = wgParsed.localAddress
                        if (wgParsed.mtu != null && wgParsed.mtu!! > 0) config.mtu = wgParsed.mtu
                        if (config.server.isNullOrEmpty() && !wgParsed.server.isNullOrEmpty()) {
                            config.server = wgParsed.server
                            config.serverPort = wgParsed.serverPort
                        }
                    }
                }

                val vkLink = if (jsonObject.has("vk") && !jsonObject.get("vk").isJsonNull) jsonObject.get("vk").asString else ""
                val streams = if (jsonObject.has("n") && !jsonObject.get("n").isJsonNull) jsonObject.get("n").asInt else 10
                val obfProfile = if (jsonObject.has("obf") && !jsonObject.get("obf").isJsonNull) jsonObject.get("obf").asString
                    else if (jsonObject.has("obfProfile") && !jsonObject.get("obfProfile").isJsonNull) jsonObject.get("obfProfile").asString
                    else ""
                val obfKey = if (jsonObject.has("key") && !jsonObject.get("key").isJsonNull) jsonObject.get("key").asString
                    else if (jsonObject.has("obfKey") && !jsonObject.get("obfKey").isJsonNull) jsonObject.get("obfKey").asString
                    else ""
                val clientId = if (jsonObject.has("cid") && !jsonObject.get("cid").isJsonNull) jsonObject.get("cid").asString
                    else if (jsonObject.has("clientId") && !jsonObject.get("clientId").isJsonNull) jsonObject.get("clientId").asString
                    else ""

                val targetProtocol = if (jsonObject.has("targetProtocol") && !jsonObject.get("targetProtocol").isJsonNull) {
                    jsonObject.get("targetProtocol").asString
                } else if (jsonObject.has("protocol") && !jsonObject.get("protocol").isJsonNull) {
                    jsonObject.get("protocol").asString
                } else if (jsonObject.has("wg") && !jsonObject.get("wg").isJsonNull && jsonObject.get("wg").asString.isNotEmpty()) {
                    "wireguard"
                } else {
                    "tcp"
                }

                // Synthesize JSON for vkturncore
                val synthesized = com.google.gson.JsonObject()
                synthesized.addProperty("server", config.server ?: "127.0.0.1")
                synthesized.addProperty("port", config.serverPort?.toIntOrNull() ?: 443)
                synthesized.addProperty("targetProtocol", targetProtocol)
                synthesized.addProperty("vkLink", vkLink)
                synthesized.addProperty("streams", streams)
                synthesized.addProperty("secretKey", config.secretKey ?: "")
                synthesized.addProperty("publicKey", config.publicKey ?: "")
                synthesized.addProperty("address", config.localAddress ?: "10.66.0.2/32")
                synthesized.addProperty("mtu", config.mtu ?: 1280)
                if (obfProfile.isNotEmpty()) synthesized.addProperty("obfProfile", obfProfile)
                if (obfKey.isNotEmpty()) synthesized.addProperty("obfKey", obfKey)
                if (clientId.isNotEmpty()) synthesized.addProperty("clientId", clientId)

                config.vkTurnRawConfig = synthesized.toString()
                config.description = "VK TURN -> $targetProtocol (${config.server.orEmpty()}:${config.serverPort.orEmpty()})"
                return config
            }

            // Standard vkturn:// format
            var remarks = "VK TURN Proxy"
            val hashIdx = rawUri.indexOf('#')
            if (hashIdx >= 0) {
                val fragment = rawUri.substring(hashIdx + 1)
                rawUri = rawUri.substring(0, hashIdx)
                if (fragment.isNotEmpty()) {
                    remarks = Utils.decodeURIComponent(fragment)
                }
            }

            val base64Part = rawUri.replace(EConfigType.VKTURN.protocolScheme, "")
            val rawJson = Utils.decode(base64Part)
            if (TextUtils.isEmpty(rawJson)) {
                return null
            }

            val config = ProfileItem.create(EConfigType.VKTURN)
            config.remarks = remarks
            populateProfileFromJson(config, rawJson)
            return config
        } catch (e: Exception) {
            return null
        }
    }

    /**
     * Populates all transport, security, and protocol fields from a JSON configuration string or embedded target URI.
     */
    fun populateProfileFromJson(config: ProfileItem, rawJson: String?) {
        if (rawJson.isNullOrBlank()) return
        try {
            val jsonObject = com.google.gson.JsonParser.parseString(rawJson).asJsonObject
            config.vkTurnRawConfig = rawJson

            // 1. Check if user provided an embedded WireGuard config
            val wgConfStr = when {
                jsonObject.has("wgConf") && !jsonObject.get("wgConf").isJsonNull -> jsonObject.get("wgConf").asString
                jsonObject.has("wg") && !jsonObject.get("wg").isJsonNull -> jsonObject.get("wg").asString
                else -> null
            }
            if (!wgConfStr.isNullOrEmpty()) {
                val wgParsed = WireguardFmt.parseWireguardConfFile(wgConfStr)
                if (!wgParsed.secretKey.isNullOrEmpty()) config.secretKey = wgParsed.secretKey
                if (!wgParsed.publicKey.isNullOrEmpty()) config.publicKey = wgParsed.publicKey
                if (!wgParsed.localAddress.isNullOrEmpty()) config.localAddress = wgParsed.localAddress
                if (wgParsed.mtu != null && wgParsed.mtu!! > 0) config.mtu = wgParsed.mtu
            }

            // 2. Check if user provided a full target URI (e.g. vless://..., trojan://..., etc.)
            val targetUri = when {
                jsonObject.has("targetUri") && !jsonObject.get("targetUri").isJsonNull -> jsonObject.get("targetUri").asString
                jsonObject.has("vlessUri") && !jsonObject.get("vlessUri").isJsonNull -> jsonObject.get("vlessUri").asString
                jsonObject.has("vlessLink") && !jsonObject.get("vlessLink").isJsonNull -> jsonObject.get("vlessLink").asString
                jsonObject.has("url") && !jsonObject.get("url").isJsonNull -> jsonObject.get("url").asString
                else -> null
            }

            if (!targetUri.isNullOrEmpty()) {
                val parsed = VlessFmt.parse(targetUri)
                    ?: TrojanFmt.parse(targetUri)
                    ?: ShadowsocksFmt.parse(targetUri)
                if (parsed != null) {
                    config.server = parsed.server
                    config.serverPort = parsed.serverPort
                    config.password = parsed.password
                    config.method = parsed.method
                    config.flow = parsed.flow
                    config.network = parsed.network
                    config.headerType = parsed.headerType
                    config.host = parsed.host
                    config.path = parsed.path
                    config.seed = parsed.seed
                    config.quicSecurity = parsed.quicSecurity
                    config.quicKey = parsed.quicKey
                    config.mode = parsed.mode
                    config.serviceName = parsed.serviceName
                    config.authority = parsed.authority
                    config.xhttpMode = parsed.xhttpMode
                    config.xhttpExtra = parsed.xhttpExtra
                    config.finalMask = parsed.finalMask
                    config.security = parsed.security
                    config.sni = parsed.sni
                    config.alpn = parsed.alpn
                    config.fingerPrint = parsed.fingerPrint
                    config.insecure = parsed.insecure
                    config.publicKey = parsed.publicKey
                    config.shortId = parsed.shortId
                    config.spiderX = parsed.spiderX
                }
            }

            // 3. Direct JSON keys take precedence or serve as primary config
            fun getString(vararg keys: String): String? {
                for (k in keys) {
                    if (jsonObject.has(k) && !jsonObject.get(k).isJsonNull) {
                        return jsonObject.get(k).asString
                    }
                }
                return null
            }

            fun getBoolean(vararg keys: String): Boolean? {
                for (k in keys) {
                    if (jsonObject.has(k) && !jsonObject.get(k).isJsonNull) {
                        return jsonObject.get(k).asBoolean
                    }
                }
                return null
            }

            getString("server", "address")?.let { config.server = it }
            getString("port")?.let { config.serverPort = it }
            getString("clientId", "clientPassword", "uuid", "password", "id")?.let { config.password = it }
            getString("flow")?.let { config.flow = it }
            getString("method", "encryption")?.let { config.method = it } ?: run {
                if (config.method.isNullOrEmpty()) config.method = "none"
            }
            getString("network", "type")?.let { config.network = it } ?: run {
                if (config.network.isNullOrEmpty()) config.network = "tcp"
            }
            getString("headerType")?.let { config.headerType = it }
            getString("host")?.let { config.host = it }
            getString("path")?.let { config.path = it }
            getString("seed")?.let { config.seed = it }
            getString("mode", "xhttpMode")?.let {
                config.mode = it
                config.xhttpMode = it
            }
            if (jsonObject.has("xhttpExtra") && jsonObject.get("xhttpExtra").isJsonObject) {
                config.xhttpExtra = jsonObject.get("xhttpExtra").toString()
            } else if (jsonObject.has("extra") && jsonObject.get("extra").isJsonObject) {
                config.xhttpExtra = jsonObject.get("extra").toString()
            } else {
                getString("extra", "xhttpExtra")?.let { config.xhttpExtra = it }
            }
            getString("serviceName")?.let { config.serviceName = it }
            getString("authority")?.let { config.authority = it }
            getString("security")?.let { config.security = it } ?: run {
                if (config.security.isNullOrEmpty()) config.security = "none"
            }
            getString("sni", "serverName")?.let { config.sni = it }
            getString("fingerprint", "fp")?.let { config.fingerPrint = it }
            getString("alpn")?.let { config.alpn = it }
            getString("publicKey", "pbk")?.let { config.publicKey = it }
            getString("shortId", "sid")?.let { config.shortId = it }
            getString("spiderX", "spx")?.let { config.spiderX = it }
            getBoolean("insecure", "allowInsecure")?.let { config.insecure = it }
            getString("finalMask", "fm")?.let { config.finalMask = it }

            // WireGuard specific direct keys
            getString("secretKey", "clientPrivateKey", "privateKey")?.let { config.secretKey = it }
            getString("localAddress", "clientAddress", "address")?.let { config.localAddress = it }
            getString("preSharedKey", "presharedkey", "psk")?.let { config.preSharedKey = it }
            getString("reserved")?.let { config.reserved = it }
            getString("mtu")?.toIntOrNull()?.let { config.mtu = it }

            val targetProtocol = getString("targetProtocol", "protocol") ?: "tcp"
            config.description = "VK TURN -> $targetProtocol (${config.server.orEmpty()}:${config.serverPort.orEmpty()})"
        } catch (e: Exception) {
            android.util.Log.e(com.v2ray.ang.AppConfig.TAG, "populateProfileFromJson error", e)
        }
    }

    /**
     * Converts a VK TURN ProfileItem object to a URI string.
     *
     * @param config the ProfileItem object to convert
     * @return the converted URI string
     */
    fun toUri(config: ProfileItem): String {
        val rawJson = config.vkTurnRawConfig.orEmpty()
        val base64 = Utils.encode(rawJson)
        return "${base64}#${Utils.encodeURIComponent(config.remarks)}"
    }
}
