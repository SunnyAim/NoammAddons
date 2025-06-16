package noammaddons.features.impl.security

import noammaddons.features.Feature
import noammaddons.ui.config.core.annotations.Config
import noammaddons.utils.ThreadUtils.loop
import noammaddons.utils.ChatUtils
import noammaddons.utils.SoundUtils
import net.minecraft.util.EnumChatFormatting
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.system.currentTimeMillis

object RatProtection : Feature() {
    
    @Config(name = "Alert Sound", description = "Play sound when suspicious activity detected")
    var alertSound = true
    
    @Config(name = "Chat Alerts", description = "Send chat notifications for detections")
    var chatAlerts = true
    
    @Config(name = "Block Requests", description = "Attempt to block suspicious requests")
    var blockRequests = true
    
    @Config(name = "Log Suspicious URLs", description = "Log all suspicious network requests")
    var logSuspiciousUrls = true
    
    // Known malicious endpoints and patterns
    private val suspiciousEndpoints = setOf(
        "discord.com/api/webhooks",
        "pastebin.com/api",
        "hastebin.com",
        "paste.ee/api",
        "api.github.com/gists",
        "requestbin.com",
        "webhook.site",
        "postman-echo.com"
    )
    
    // Patterns that indicate session stealing attempts
    private val sessionTheftPatterns = listOf(
        "accessToken",
        "session.token",
        "playerID",
        "uuid",
        "session.playerID",
        "mc.session"
    )
    
    // Track network requests and their frequency
    private val requestTracker = ConcurrentHashMap<String, MutableList<Long>>()
    private val blockedRequests = CopyOnWriteArrayList<String>()
    private val detectionLog = CopyOnWriteArrayList<SecurityEvent>()
    
    data class SecurityEvent(
        val timestamp: Long,
        val type: ThreatType,
        val details: String,
        val severity: Severity
    )
    
    enum class ThreatType {
        SUSPICIOUS_ENDPOINT,
        SESSION_ACCESS,
        RAPID_REQUESTS,
        DATA_EXFILTRATION,
        UNKNOWN_NETWORK_ACTIVITY
    }
    
    enum class Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }
    
    init {
        // Monitor network activity every 100ms (less aggressive than original)
        loop(100) {
            if (!enabled) return@loop
            if (mc.theWorld == null) return@loop
            
            monitorNetworkActivity()
            checkForSuspiciousPatterns()
            cleanupOldRequests()
        }
        
        // Hook into HTTP request creation to monitor outgoing requests
        interceptNetworkRequests()
    }
    
    private fun monitorNetworkActivity() {
        // This would ideally hook into the actual network layer
        // For demonstration, we're showing the structure
        
        // Check for excessive requests to any single endpoint
        requestTracker.forEach { (endpoint, requests) ->
            val recentRequests = requests.filter { 
                currentTimeMillis() - it < 5000 // Last 5 seconds
            }
            
            if (recentRequests.size > 10) { // More than 10 requests in 5 seconds
                logThreat(
                    ThreatType.RAPID_REQUESTS,
                    "Excessive requests to $endpoint: ${recentRequests.size} in 5 seconds",
                    Severity.MEDIUM
                )
            }
        }
    }
    
    private fun interceptNetworkRequests() {
        // This is a conceptual approach - actual implementation would need
        // to hook into the HTTP client or network layer
        
        // Example of how to check requests before they're sent
        fun checkHttpRequest(request: HttpRequest): Boolean {
            val uri = request.uri().toString()
            val body = getRequestBody(request) // Would need actual implementation
            
            // Check if request is going to suspicious endpoint
            if (suspiciousEndpoints.any { uri.contains(it, ignoreCase = true) }) {
                logThreat(
                    ThreatType.SUSPICIOUS_ENDPOINT,
                    "Request to suspicious endpoint: $uri",
                    Severity.HIGH
                )
                
                if (blockRequests) {
                    alertUser("BLOCKED: Suspicious request to $uri")
                    return false // Block the request
                }
            }
            
            // Check if request contains session data
            if (body != null && sessionTheftPatterns.any { body.contains(it, ignoreCase = true) }) {
                logThreat(
                    ThreatType.SESSION_ACCESS,
                    "Request contains potential session data to: $uri",
                    Severity.CRITICAL
                )
                
                if (blockRequests) {
                    alertUser("CRITICAL: Blocked request containing session data!")
                    return false
                }
            }
            
            // Log the request for monitoring
            trackRequest(uri)
            
            return true // Allow the request
        }
    }
    
    private fun checkForSuspiciousPatterns() {
        // Monitor for code patterns that indicate malicious behavior
        
        // This would scan loaded classes/mods for suspicious code patterns
        // Implementation would depend on the mod loader's capabilities
        
        // Example checks:
        // - Classes accessing mc.session frequently
        // - Obfuscated network code
        // - Suspicious string patterns in loaded code
    }
    
    private fun trackRequest(endpoint: String) {
        val now = currentTimeMillis()
        requestTracker.computeIfAbsent(endpoint) { mutableListOf() }.add(now)
    }
    
    private fun cleanupOldRequests() {
        val cutoff = currentTimeMillis() - 60000 // Keep last minute of data
        requestTracker.values.forEach { requests ->
            requests.removeIf { it < cutoff }
        }
    }
    
    private fun logThreat(type: ThreatType, details: String, severity: Severity) {
        val event = SecurityEvent(currentTimeMillis(), type, details, severity)
        detectionLog.add(event)
        
        // Keep only last 100 events
        if (detectionLog.size > 100) {
            detectionLog.removeAt(0)
        }
        
        // Alert user based on severity
        when (severity) {
            Severity.CRITICAL -> {
                alertUser("${EnumChatFormatting.DARK_RED}CRITICAL THREAT: $details")
                if (alertSound) SoundUtils.playErrorSound()
            }
            Severity.HIGH -> {
                alertUser("${EnumChatFormatting.RED}HIGH THREAT: $details")
                if (alertSound) SoundUtils.playWarningSound()
            }
            Severity.MEDIUM -> {
                if (chatAlerts) alertUser("${EnumChatFormatting.YELLOW}MEDIUM THREAT: $details")
            }
            Severity.LOW -> {
                if (logSuspiciousUrls) println("Low threat detected: $details")
            }
        }
        
        // Log to file if enabled
        if (logSuspiciousUrls) {
            logToFile(event)
        }
    }
    
    private fun alertUser(message: String) {
        if (chatAlerts) {
            ChatUtils.sendMessage("${EnumChatFormatting.BOLD}[RAT PROTECTION] $message")
        }
    }
    
    private fun logToFile(event: SecurityEvent) {
        // Implementation would write to a log file
        // Format: [timestamp] [severity] [type] details
        val logMessage = "[${event.timestamp}] [${event.severity}] [${event.type}] ${event.details}"
        println(logMessage) // Placeholder - would write to actual file
    }
    
    private fun getRequestBody(request: HttpRequest): String? {
        // This would need actual implementation to extract request body
        // Depends on the HTTP client being used
        return null
    }
    
    // Public API for other mods to report suspicious activity
    fun reportSuspiciousActivity(description: String, severity: Severity = Severity.MEDIUM) {
        logThreat(ThreatType.UNKNOWN_NETWORK_ACTIVITY, "External report: $description", severity)
    }
    
    // Get recent security events for display in GUI
    fun getRecentEvents(limit: Int = 10): List<SecurityEvent> {
        return detectionLog.takeLast(limit)
    }
    
    // Check if a URL is known to be suspicious
    fun isSuspiciousUrl(url: String): Boolean {
        return suspiciousEndpoints.any { url.contains(it, ignoreCase = true) }
    }
}
