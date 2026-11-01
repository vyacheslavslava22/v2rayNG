package com.v2ray.ang.handler

import com.v2ray.ang.AngApplication
import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.LauncherManager
import com.v2ray.ang.util.JsonUtil
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.Utils

/**
 * Applies Happ routing profiles ([HappLinkParser]) to this app's routing settings.
 *
 * This app has one active rule list, so both Happ modes (`add` and `onadd`) replace the
 * current unlocked rules with the profile; locked rules are kept by
 * [SettingsManager.resetRoutingRulesets].
 */
object HappRoutingImporter {

    /** Settings key prefix remembering the last routing header applied per subscription. */
    private const val KEY_SUB_ROUTING_APPLIED_PREFIX = "pref_sub_routing_applied_"

    /**
     * Imports every `happ://routing/` link found in [text].
     *
     * @return number of routing profiles applied.
     */
    fun importFromText(text: String?): Int {
        val links = HappLinkParser.extractRoutingLinks(text)
        if (links.isEmpty()) return 0
        var applied = 0
        links.forEach { link ->
            if (applyLink(link)) applied++
        }
        if (applied > 0) restartServiceIfRunning()
        return applied
    }

    /**
     * Applies the routing profile a subscription panel sends in its `routing` response header,
     * once per distinct header value, when the user has not disabled it.
     */
    fun applyFromSubscriptionHeader(subId: String, header: String?) {
        val value = header?.trim().orEmpty()
        if (value.isEmpty() || !HappLinkParser.isRoutingLink(value)) return
        if (!MmkvManager.decodeSettingsBool(AppConfig.PREF_APPLY_SUB_ROUTING, true)) return

        val key = KEY_SUB_ROUTING_APPLIED_PREFIX + subId
        val fingerprint = value.hashCode().toString()
        if (MmkvManager.decodeSettingsString(key) == fingerprint) return

        if (applyLink(value)) {
            MmkvManager.encodeSettings(key, fingerprint)
            LogUtil.i(AppConfig.TAG, "HappRoutingImporter: applied routing header for subscription $subId")
            restartServiceIfRunning()
        }
    }

    private fun applyLink(link: String): Boolean {
        val profile = HappLinkParser.decodeRoutingLink(link, Utils::decode)
        if (profile == null) {
            LogUtil.w(AppConfig.TAG, "HappRoutingImporter: invalid routing profile link")
            return false
        }
        val rules = HappLinkParser.toRulesets(profile)
        if (rules.isEmpty()) {
            LogUtil.w(AppConfig.TAG, "HappRoutingImporter: routing profile has no rules")
            return false
        }
        if (!SettingsManager.resetRoutingRulesets(JsonUtil.toJson(rules))) {
            return false
        }
        HappLinkParser.domainStrategy(profile)?.let {
            MmkvManager.encodeSettings(AppConfig.PREF_ROUTING_DOMAIN_STRATEGY, it)
        }
        HappLinkParser.remoteDns(profile)?.let {
            MmkvManager.encodeSettings(AppConfig.PREF_REMOTE_DNS, it)
        }
        HappLinkParser.domesticDns(profile)?.let {
            MmkvManager.encodeSettings(AppConfig.PREF_DOMESTIC_DNS, it)
        }
        return true
    }

    /** The daemon ignores the restart message when the core is not running. */
    private fun restartServiceIfRunning() {
        try {
            LauncherManager.restartService(AngApplication.application)
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "HappRoutingImporter: failed to request service restart", e)
        }
    }
}
