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
            config.server = server
            config.serverPort = port
            config.description = "VK TURN -> $targetProtocol ($server:$port)"
            config.vkTurnRawConfig = rawJson

            if (jsonObject.has("clientId") && !jsonObject.get("clientId").isJsonNull) {
                config.password = jsonObject.get("clientId").asString
            } else if (jsonObject.has("clientPassword") && !jsonObject.get("clientPassword").isJsonNull) {
                config.password = jsonObject.get("clientPassword").asString
            }
            if (jsonObject.has("flow") && !jsonObject.get("flow").isJsonNull) {
                config.flow = jsonObject.get("flow").asString
            }
            if (jsonObject.has("method") && !jsonObject.get("method").isJsonNull) {
                config.method = jsonObject.get("method").asString
            } else {
                config.method = "none"
            }
            if (jsonObject.has("network") && !jsonObject.get("network").isJsonNull) {
                config.network = jsonObject.get("network").asString
            } else {
                config.network = "tcp"
            }
            if (jsonObject.has("security") && !jsonObject.get("security").isJsonNull) {
                config.security = jsonObject.get("security").asString
            } else {
                config.security = "none"
            }
            if (jsonObject.has("sni") && !jsonObject.get("sni").isJsonNull) {
                config.sni = jsonObject.get("sni").asString
            }
            if (jsonObject.has("path") && !jsonObject.get("path").isJsonNull) {
                config.path = jsonObject.get("path").asString
            }
            if (jsonObject.has("host") && !jsonObject.get("host").isJsonNull) {
                config.host = jsonObject.get("host").asString
            }

            return config
        } catch (e: Exception) {
            return null
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
