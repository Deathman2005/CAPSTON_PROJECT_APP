package com.smsshield.app.data.local

import androidx.room.Entity
import androidx.room.PrimaryKey
import com.smsshield.domain.model.ScanItem
import com.smsshield.domain.model.SecurityClassification
import java.util.UUID

/**
 * Room entity representing minimal scan metadata.
 *
 * NON-NEGOTIABLE PRIVACY ENFORCEMENT:
 * Full message text is NEVER stored in this database.
 * Only classification, calculated risk score, URL count, and rule triggers are retained.
 */
@Entity(tableName = "scan_records")
data class ScanRecordEntity(
    @PrimaryKey
    val id: String = UUID.randomUUID().toString(),
    val timestamp: Long = System.currentTimeMillis(),
    val classification: String,
    val riskScore: Double?,
    val confidence: Double,
    val urlCount: Int,
    val extractedUrlsString: String,
    val detectionReasonsString: String,
    val recommendation: String,
    val sourceCategory: String
) {
    fun toDomain(): ScanItem {
        val classEnum = try {
            SecurityClassification.valueOf(classification)
        } catch (e: Exception) {
            SecurityClassification.UNKNOWN
        }

        val urls = if (extractedUrlsString.isBlank()) emptyList() else extractedUrlsString.split("||")
        val reasons = if (detectionReasonsString.isBlank()) emptyList() else detectionReasonsString.split("||")

        return ScanItem(
            id = id,
            timestamp = timestamp,
            classification = classEnum,
            riskScore = riskScore,
            confidence = confidence,
            urlCount = urlCount,
            extractedUrls = urls,
            detectionReasons = reasons,
            recommendation = recommendation,
            sourceCategory = sourceCategory
        )
    }

    companion object {
        fun fromDomain(item: ScanItem): ScanRecordEntity {
            return ScanRecordEntity(
                id = item.id,
                timestamp = item.timestamp,
                classification = item.classification.name,
                riskScore = item.riskScore,
                confidence = item.confidence,
                urlCount = item.urlCount,
                extractedUrlsString = item.extractedUrls.joinToString("||"),
                detectionReasonsString = item.detectionReasons.joinToString("||"),
                recommendation = item.recommendation,
                sourceCategory = item.sourceCategory
            )
        }
    }
}
