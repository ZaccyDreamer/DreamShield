package com.dreamshield.app

import org.junit.Assert.*
import org.junit.Test

class DomainRulesTest {
    @Test fun parsesHostsAndDnsFilterSyntax() {
        val domains = DomainRules.parse("""
            0.0.0.0 ads.example tracker.example
            ||bad.cdn.test^
            ! comment
            @@||allowed.example^
        """.trimIndent())
        assertTrue("ads.example" in domains)
        assertTrue("tracker.example" in domains)
        assertTrue("bad.cdn.test" in domains)
        assertFalse("allowed.example" in domains)
    }

    @Test fun allowlistWinsAndSubdomainsMatch() {
        val rules = DomainRules(setOf("ads.example"), setOf("safe.ads.example"), setOf("custom.test"))
        assertTrue(rules.isBlocked("img.ads.example"))
        assertFalse(rules.isBlocked("safe.ads.example"))
        assertTrue(rules.isBlocked("sub.custom.test"))
        assertFalse(rules.isBlocked("good.example"))
    }

    @Test fun adguardExceptionsBecomeAllowRulesAndConditionalRulesAreSkipped() {
        val feed = DomainRules.parseFilter("""
            ||ads.example^
            @@||safe.ads.example^
            ||conditional.example^$dnstype=AAAA
        """.trimIndent())
        val rules = DomainRules(feed.blocked, feed.allowed, emptySet())
        assertTrue(rules.isBlocked("ads.example"))
        assertFalse(rules.isBlocked("safe.ads.example"))
        assertFalse(rules.isBlocked("conditional.example"))
    }
}
