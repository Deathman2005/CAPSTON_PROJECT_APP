package com.smsshield.app.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanRecordDao {

    @Query("SELECT * FROM scan_records ORDER BY timestamp DESC")
    fun getAllScans(): Flow<List<ScanRecordEntity>>

    @Query("SELECT * FROM scan_records ORDER BY timestamp DESC LIMIT :limit")
    fun getRecentScans(limit: Int): Flow<List<ScanRecordEntity>>

    @Query("SELECT COUNT(*) FROM scan_records")
    fun getTotalScanCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM scan_records WHERE classification = :classification")
    fun getScanCountByClassification(classification: String): Flow<Int>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScan(scan: ScanRecordEntity)

    @Query("DELETE FROM scan_records WHERE id = :id")
    suspend fun deleteScan(id: String)

    @Query("DELETE FROM scan_records")
    suspend fun clearAllScans()
}

