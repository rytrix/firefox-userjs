// Let google scan files for malware
user_pref("browser.safebrowsing.downloads.remote.enabled", true);

// No letterbox and add back webgl
user_pref("privacy.resistFingerprinting.letterboxing", false); // 4504 [pointless if not using RFP]
user_pref("webgl.disabled", false); // 4520 [mostly pointless if not using RFP]

// Session Restore
user_pref("browser.startup.page", 3); // 0102: 0=blank, 1=home, 2=last visited page, 3=resume previous session
user_pref("privacy.clearOnShutdown.history", false); // 2811 FF127 or lower
user_pref("privacy.clearOnShutdown_v2.historyFormDataAndDownloads", false); // 2811 FF128+
