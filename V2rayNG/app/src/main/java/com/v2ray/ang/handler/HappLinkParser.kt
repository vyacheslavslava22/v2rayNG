package com.v2ray.ang.handler

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.RulesetItem
import java.net.URLDecoder
import java.util.Locale

/**
 * Compatibility layer for links made for the Happ client, so users can switch to this app
 * without asking their provider for new links:
 *
 * - `happ://add/<subscription or config url>` — import a subscription or a single config.
 * - `happ://routing/add/<base64 json>` and `happ://routing/onadd/<base64 json>` — import a
 *   routing profile (direct / proxy / block lists, DNS, domain strategy).
 * - `happ://crypt.../...` — links encrypted with Happ's proprietary key. They are detected only
 *   to show a clear message; this app does not and must not decrypt them.
 *
 * Pure functions only (no Android or storage calls) so the logic is covered by JVM tests.
 */
object HappLinkParser {
    private const val SCHEME = "happ://"
    private const val ADD_PREFIX = "happ://add/"
    private const val ROUTING_PREFIX = "happ://routing/"
    private val CRYPT_REGEX = Regex("^happ://crypt[0-9]*/", RegexOption.IGNORE_CASE)

    /** Upper bound for a decoded routing profile; real profiles are a few kilobytes. */
    private const val MAX_PROFILE_JSON_LENGTH = 512 * 1024

    private val VALID_DOMAIN_STRATEGIES = setOf("AsIs", "IPIfNonMatch", "IPOnDemand")

    /**
     * Happ profiles are usually written for the runetfreedom/Loyalsoldier geosite files. These tags
     * do not exist in the geosite.dat this app ships, and Xray refuses to start when a rule
     * references a missing tag, so they are mapped to the equivalent v2fly category.
     */
    private val GEOSITE_ALIASES = mapOf(
        "geosite:ru" to "geosite:category-ru",
        "geosite:geolocation-ru" to "geosite:category-ru",
    )

    private val gson = Gson()

    fun isHappLink(text: String?): Boolean =
        text?.trim()?.startsWith(SCHEME, ignoreCase = true) == true

    fun isRoutingLink(text: String?): Boolean =
        text?.trim()?.startsWith(ROUTING_PREFIX, ignoreCase = true) == true

    fun isEncryptedLink(text: String?): Boolean =
        text?.trim()?.let { CRYPT_REGEX.containsMatchIn(it) } == true

    /** True when [text] contains at least one encrypted Happ link on any line. */
    fun containsEncryptedLink(text: String?): Boolean =
        text?.lines()?.any { isEncryptedLink(it) } == true

    /**
     * Returns the URL wrapped by a `happ://add/` link, or null when [line] is not such a link.
     * The wrapped URL may be percent-encoded; it is decoded only when it does not already look
     * like a plain URL, so a literal `+` in a plain URL is kept.
     */
    fun unwrapAddLink(line: String?): String? {
        val value = line?.trim().orEmpty()
        if (!value.startsWith(ADD_PREFIX, ignoreCase = true)) return null
        val inner = value.substring(ADD_PREFIX.length).trim()
        if (inner.isEmpty()) return null
        if (inner.contains("://")) return inner
        val decoded = runCatching { URLDecoder.decode(inner, "UTF-8") }.getOrNull() ?: return null
        return decoded.trim().takeIf { it.contains("://") }
    }

    /**
     * Rewrites import text line by line: `happ://add/` links become the URL they wrap, routing and
     * encrypted Happ links are removed (they are handled separately), other lines are kept.
     */
    fun normalizeImportText(text: String?): String? {
        if (text == null || !text.contains(SCHEME, ignoreCase = true)) return text
        return text.lines().mapNotNull { line ->
            when {
                isRoutingLink(line) || isEncryptedLink(line) -> null
                else -> unwrapAddLink(line) ?: line
            }
        }.joinToString("\n")
    }

    /** All `happ://routing/...` links found in [text], one per line. */
    fun extractRoutingLinks(text: String?): List<String> =
        text?.lines()?.map { it.trim() }?.filter { isRoutingLink(it) }.orEmpty()

    /**
     * Decodes a `happ://routing/<mode>/<base64>` link.
     *
     * @param decodeBase64 Base64 decoder (standard or URL-safe); injected for JVM tests.
     * @return null when the link or its JSON is invalid.
     */
    fun decodeRoutingLink(link: String?, decodeBase64: (String) -> String): HappRoutingProfile? {
        val value = link?.trim().orEmpty()
        if (!isRoutingLink(value)) return null
        val payload = value.substringAfterLast('/').trim()
        if (payload.isEmpty()) return null
        val unescaped = if (payload.contains('%')) {
            runCatching { URLDecoder.decode(payload, "UTF-8") }.getOrDefault(payload)
        } else {
            payload
        }
        val json = runCatching { decodeBase64(unescaped) }.getOrNull()?.trim().orEmpty()
        if (json.isEmpty() || json.length > MAX_PROFILE_JSON_LENGTH || !json.startsWith("{")) return null
        return runCatching { gson.fromJson(json, HappRoutingProfile::class.java) }.getOrNull()
    }

    /**
     * Converts a Happ routing profile into this app's routing rules, honoring the profile's
     * `RouteOrder` (default: block, proxy, direct) and `GlobalProxy` (false = unmatched traffic
     * goes direct).
     */
    fun toRulesets(profile: HappRoutingProfile): List<RulesetItem> {
        val prefix = profile.name?.trim()?.takeIf { it.isNotEmpty() }?.take(40) ?: "Happ"
        val rules = mutableListOf<RulesetItem>()
        for (tag in parseRouteOrder(profile.routeOrder)) {
            val (sites, ips, label) = when (tag) {
                AppConfig.TAG_BLOCKED -> Triple(profile.blockSites, profile.blockIp, "Block")
                AppConfig.TAG_PROXY -> Triple(profile.proxySites, profile.proxyIp, "Proxy")
                else -> Triple(profile.directSites, profile.directIp, "Direct")
            }
            normalizeDomains(sites)?.let {
                rules.add(RulesetItem(remarks = "$prefix: $label sites", domain = it, outboundTag = tag))
            }
            normalizeIps(ips)?.let {
                rules.add(RulesetItem(remarks = "$prefix: $label IP", ip = it, outboundTag = tag))
            }
        }
        if (isFalse(profile.globalProxy)) {
            rules.add(
                RulesetItem(
                    remarks = "$prefix: Everything else direct",
                    port = "0-65535",
                    outboundTag = AppConfig.TAG_DIRECT
                )
            )
        }
        return rules
    }

    /** The profile's domain strategy when it is one Xray accepts, otherwise null. */
    fun domainStrategy(profile: HappRoutingProfile): String? =
        profile.domainStrategy?.trim()?.let { value ->
            VALID_DOMAIN_STRATEGIES.firstOrNull { it.equals(value, ignoreCase = true) }
        }

    /** Remote (proxied) DNS server: a DoH URL when given, otherwise a plain IP. */
    fun remoteDns(profile: HappRoutingProfile): String? =
        pickDns(profile.remoteDnsType, profile.remoteDnsDomain, profile.remoteDnsIp)

    /** Domestic (direct) DNS server: a DoH URL when given, otherwise a plain IP. */
    fun domesticDns(profile: HappRoutingProfile): String? =
        pickDns(profile.domesticDnsType, profile.domesticDnsDomain, profile.domesticDnsIp)

    private fun pickDns(type: String?, domain: String?, ip: String?): String? {
        val url = domain?.trim().orEmpty()
        if (type.equals("DoH", ignoreCase = true) && url.startsWith("https://", ignoreCase = true)) {
            return url
        }
        return ip?.trim()?.takeIf { isIpLiteral(it) }
    }

    private fun isIpLiteral(value: String): Boolean {
        if (value.isEmpty() || value.length > 45) return false
        val ipv4 = Regex("^((25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1?\\d?\\d)$")
        if (ipv4.matches(value)) return true
        return value.contains(':') && value.all { it.isLetterOrDigit() || it == ':' || it == '.' }
    }

    private fun parseRouteOrder(raw: String?): List<String> {
        val defaultOrder = listOf(AppConfig.TAG_BLOCKED, AppConfig.TAG_PROXY, AppConfig.TAG_DIRECT)
        val tokens = raw?.lowercase(Locale.ROOT)
            ?.split('-', ',', ' ')
            ?.map { it.trim() }
            ?.mapNotNull {
                when (it) {
                    "block" -> AppConfig.TAG_BLOCKED
                    "proxy" -> AppConfig.TAG_PROXY
                    "direct" -> AppConfig.TAG_DIRECT
                    else -> null
                }
            }
            ?.distinct()
            .orEmpty()
        // Append any category the profile omitted so its rules are never silently dropped.
        return tokens + defaultOrder.filter { it !in tokens }
    }

    private fun normalizeDomains(list: List<String>?): List<String>? =
        list.orEmpty()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { GEOSITE_ALIASES[it.lowercase(Locale.ROOT)] ?: it }
            .distinct()
            .takeIf { it.isNotEmpty() }

    private fun normalizeIps(list: List<String>?): List<String>? =
        list.orEmpty()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
            .takeIf { it.isNotEmpty() }

    private fun isFalse(value: String?): Boolean =
        value?.trim().equals("false", ignoreCase = true) || value?.trim() == "0"
}

/**
 * Routing profile JSON used by Happ links. Field names follow Happ's format; all fields are
 * optional and kept as strings because generators write booleans both as `true` and `"true"`.
 */
data class HappRoutingProfile(
    @SerializedName("Name") var name: String? = null,
    @SerializedName("GlobalProxy") var globalProxy: String? = null,
    @SerializedName("RouteOrder") var routeOrder: String? = null,
    @SerializedName("RemoteDNSType") var remoteDnsType: String? = null,
    @SerializedName("RemoteDNSDomain") var remoteDnsDomain: String? = null,
    @SerializedName("RemoteDNSIP") var remoteDnsIp: String? = null,
    @SerializedName("DomesticDNSType") var domesticDnsType: String? = null,
    @SerializedName("DomesticDNSDomain") var domesticDnsDomain: String? = null,
    @SerializedName("DomesticDNSIP") var domesticDnsIp: String? = null,
    @SerializedName("DirectSites") var directSites: List<String>? = null,
    @SerializedName("DirectIp") var directIp: List<String>? = null,
    @SerializedName("ProxySites") var proxySites: List<String>? = null,
    @SerializedName("ProxyIp") var proxyIp: List<String>? = null,
    @SerializedName("BlockSites") var blockSites: List<String>? = null,
    @SerializedName("BlockIp") var blockIp: List<String>? = null,
    @SerializedName("DomainStrategy") var domainStrategy: String? = null,
)
