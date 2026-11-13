# Add project specific ProGuard rules here.
-keepattributes *Annotation*
-keepclassmembers class * {
    @org.jetbrains.annotations.* <fields>;
    @org.jetbrains.annotations.* <methods>;
}

# Preserve domain and API data models for Gson / Room / Serialization
-keep class com.smsshield.domain.model.** { *; }
-keep class com.smsshield.app.data.local.** { *; }
-keep class com.smsshield.app.data.remote.** { *; }
