package com.v2ray.ang.fmt

import android.text.TextUtils
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.util.Utils

object VkTurnFmt : FmtBase() {
    /**
     * Parses a VK TURN URI string into a ProfileItem object.
     * Format: vkturn://<base64-encoded-JSON-config>#<remarks-url-encoded>
     *
     * @param str the VK TURN URI string to parse
     * @return the parsed ProfileItem object, or null if parsing fails
     */
    fun parse(str: String): ProfileItem? {
        try {
            var rawUri = str
            var remarks = "VK TURN Proxy"

            val hashIdx = str.indexOf('#')
            if (hashIdx >= 0) {
                rawUri = str.substring(0, hashIdx)
                val fragment = str.substring(hashIdx + 1)
                if (fragment.isNotEmpty()) {
                    remarks = Utils.decodeURIComponent(fragment)
                }
            }

            val base64Part = rawUri.replace(EConfigType.VKTURN.protocolScheme, "")
            val rawJson = Utils.decode(base64Part)
            if (TextUtils.isEmpty(rawJson)) {
                return null
            }

            // Verify it is a valid JSON
            val jsonObject = com.google.gson.JsonParser.parseString(rawJson).asJsonObject
            val server = if (jsonObject.has("server")) jsonObject.get("server").asString else "127.0.0.1"
            val port = if (jsonObject.has("port")) jsonObject.get("port").asString else "443"
            val targetProtocol = if (jsonObject.has("targetProtocol")) jsonObject.get("targetProtocol").asString else "vless"

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

            // 1. Check if user provided a full target URI (e.g. vless://..., trojan://..., etc.)
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

            // 2. Direct JSON keys take precedence or serve as primary config
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

            val targetProtocol = getString("targetProtocol", "protocol") ?: "vless"
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
