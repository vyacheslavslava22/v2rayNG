package com.v2ray.ang.handler

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Base64

class HappLinkParserTest {
    private val decode: (String) -> String = { String(Base64.getDecoder().decode(it), Charsets.UTF_8) }

    private fun routingLink(json: String, mode: String = "onadd") =
        "happ://routing/$mode/" + Base64.getEncoder().encodeToString(json.toByteArray())

    @Test
    fun detectsLinkKinds() {
        assertTrue(HappLinkParser.isHappLink("  happ://add/https://example.com/sub"))
        assertTrue(HappLinkParser.isRoutingLink("HAPP://routing/add/abc"))
        assertTrue(HappLinkParser.isEncryptedLink("happ://crypt3/AAAA"))
        assertTrue(HappLinkParser.isEncryptedLink("happ://crypt/AAAA"))
        assertFalse(HappLinkParser.isEncryptedLink("happ://add/https://x.y"))
        assertFalse(HappLinkParser.isHappLink("vless://uuid@host:443"))
        assertFalse(HappLinkParser.isHappLink(null))
        assertTrue(HappLinkParser.containsEncryptedLink("vless://a\nhapp://crypt2/BBB"))
        assertFalse(HappLinkParser.containsEncryptedLink(""))
    }

    @Test
    fun unwrapsPlainAndEncodedAddLinks() {
        assertEquals("https://sub.example.com/abc?x=1+2", HappLinkParser.unwrapAddLink("happ://add/https://sub.example.com/abc?x=1+2"))
        assertEquals("https://sub.example.com/a b", HappLinkParser.unwrapAddLink("happ://add/https%3A%2F%2Fsub.example.com%2Fa%20b"))
        assertNull(HappLinkParser.unwrapAddLink("happ://add/"))
        assertNull(HappLinkParser.unwrapAddLink("happ://add/not-a-url"))
        assertNull(HappLinkParser.unwrapAddLink("https://example.com"))
    }

    @Test
    fun normalizeKeepsOtherLinesAndDropsRoutingAndCrypt() {
        val text = listOf(
            "happ://add/https://sub.example.com/1",
            "vless://uuid@host:443#name",
            "happ://routing/onadd/e30=",
            "happ://crypt4/secret",
        ).joinToString("\n")
        assertEquals(
            "https://sub.example.com/1\nvless://uuid@host:443#name",
            HappLinkParser.normalizeImportText(text)
        )
        // Text without Happ links is returned unchanged.
        assertEquals("vmess://abc", HappLinkParser.normalizeImportText("vmess://abc"))
        assertNull(HappLinkParser.normalizeImportText(null))
        assertEquals("", HappLinkParser.normalizeImportText("happ://routing/add/e30="))
    }

    @Test
    fun decodesRoutingProfileWithStringAndBooleanFlags() {
        val json = """
            {"Name":"RU","GlobalProxy":true,"RouteOrder":"block-proxy-direct",
             "DirectSites":["geosite:ru","domain:vk.com"," ","geosite:geolocation-ru"],
             "DirectIp":["geoip:ru","geoip:private"],
             "BlockSites":["geosite:category-ads-all"],
             "DomainStrategy":"ipifnonmatch",
             "RemoteDNSType":"DoH","RemoteDNSDomain":"https://dns.google/dns-query","RemoteDNSIP":"8.8.8.8",
             "DomesticDNSType":"DoU","DomesticDNSDomain":"dns.yandex","DomesticDNSIP":"77.88.8.8"}
        """.trimIndent()
        val profile = HappLinkParser.decodeRoutingLink(routingLink(json), decode)
        assertNotNull(profile)
        profile!!
        assertEquals("true", profile.globalProxy)

        val rules = HappLinkParser.toRulesets(profile)
        assertEquals(3, rules.size)
        assertEquals("block", rules[0].outboundTag)
        assertEquals(listOf("geosite:category-ads-all"), rules[0].domain)
        assertEquals("direct", rules[1].outboundTag)
        // Unsupported geosite tags are mapped and de-duplicated; blank entries are removed.
        assertEquals(listOf("geosite:category-ru", "domain:vk.com"), rules[1].domain)
        assertEquals(listOf("geoip:ru", "geoip:private"), rules[2].ip)
        assertEquals("RU: Direct IP", rules[2].remarks)

        assertEquals("IPIfNonMatch", HappLinkParser.domainStrategy(profile))
        assertEquals("https://dns.google/dns-query", HappLinkParser.remoteDns(profile))
        assertEquals("77.88.8.8", HappLinkParser.domesticDns(profile))
    }

    @Test
    fun globalProxyFalseAddsDirectCatchAllAndCustomOrder() {
        val json = """{"GlobalProxy":"false","RouteOrder":"direct-proxy","ProxySites":["domain:youtube.com"],"DirectSites":["domain:ya.ru"],"BlockIp":["1.2.3.4/32"]}"""
        val rules = HappLinkParser.toRulesets(HappLinkParser.decodeRoutingLink(routingLink(json, "add"), decode)!!)
        assertEquals(listOf("direct", "proxy", "block", "direct"), rules.map { it.outboundTag })
        assertEquals("0-65535", rules.last().port)
        assertEquals("Happ: Direct sites", rules.first().remarks)
    }

    @Test
    fun invalidRoutingLinksGiveNull() {
        assertNull(HappLinkParser.decodeRoutingLink("happ://routing/onadd/", decode))
        assertNull(HappLinkParser.decodeRoutingLink("happ://add/https://x.y", decode))
        assertNull(HappLinkParser.decodeRoutingLink(routingLink("[1,2]"), decode))
        assertNull(HappLinkParser.decodeRoutingLink("happ://routing/onadd/!!!", { throw IllegalArgumentException() }))
        assertNull(HappLinkParser.decodeRoutingLink(routingLink("{not json"), decode))
    }

    @Test
    fun invalidDnsAndStrategyAreIgnored() {
        val profile = HappRoutingProfile(
            remoteDnsType = "DoU", remoteDnsDomain = "https://ignored", remoteDnsIp = "dns.google",
            domesticDnsIp = "2a02:6b8::feed:0ff", domainStrategy = "Fastest",
        )
        assertNull(HappLinkParser.remoteDns(profile))
        assertEquals("2a02:6b8::feed:0ff", HappLinkParser.domesticDns(profile))
        assertNull(HappLinkParser.domainStrategy(profile))
        assertTrue(HappLinkParser.toRulesets(profile).isEmpty())
    }
}
