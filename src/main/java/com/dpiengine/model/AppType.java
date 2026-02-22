package com.dpiengine.model;

/**
 * Application type identified by DPI analysis.
 * Equivalent to the C++ AppType enum class in types.h
 */
public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK,
    TWITTER,
    INSTAGRAM,
    TIKTOK,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    GITHUB,
    CLOUDFLARE,
    TWITCH,
    DISCORD,
    REDDIT,
    LINKEDIN,
    WHATSAPP,
    TELEGRAM,
    ZOOM,
    DROPBOX;

    /**
     * Maps an SNI (Server Name Indication) hostname to an AppType.
     * Equivalent to sniToAppType() in types.cpp
     */
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isBlank()) return UNKNOWN;
        String lower = sni.toLowerCase();

        if (lower.contains("youtube") || lower.contains("googlevideo")) return YOUTUBE;
        if (lower.contains("facebook") || lower.contains("fbcdn"))       return FACEBOOK;
        if (lower.contains("twitter") || lower.contains("twimg"))        return TWITTER;
        if (lower.contains("instagram"))                                  return INSTAGRAM;
        if (lower.contains("tiktok"))                                     return TIKTOK;
        if (lower.contains("netflix"))                                    return NETFLIX;
        if (lower.contains("amazon") || lower.contains("amazonaws"))      return AMAZON;
        if (lower.contains("microsoft") || lower.contains("live.com"))    return MICROSOFT;
        if (lower.contains("apple") || lower.contains("icloud"))          return APPLE;
        if (lower.contains("github"))                                     return GITHUB;
        if (lower.contains("cloudflare"))                                 return CLOUDFLARE;
        if (lower.contains("twitch"))                                     return TWITCH;
        if (lower.contains("discord"))                                    return DISCORD;
        if (lower.contains("reddit"))                                     return REDDIT;
        if (lower.contains("linkedin"))                                   return LINKEDIN;
        if (lower.contains("whatsapp"))                                   return WHATSAPP;
        if (lower.contains("telegram"))                                   return TELEGRAM;
        if (lower.contains("zoom"))                                       return ZOOM;
        if (lower.contains("dropbox"))                                    return DROPBOX;
        if (lower.contains("google"))                                     return GOOGLE;

        return UNKNOWN;
    }
}
