package com.smsshield.app.ui.scanner

import android.view.View
import android.widget.ImageButton
import com.journeyapps.barcodescanner.CaptureActivity
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import com.smsshield.app.R

/**
 * Dedicated Portrait-Locked QR Code Capture Activity.
 * Provides a centered square framing box optimized for small (2x2 cm) to standard UPI QR codes.
 */
class PortraitCaptureActivity : CaptureActivity() {

    private var isTorchOn: Boolean = false

    override fun initializeContent(): DecoratedBarcodeView {
        setContentView(R.layout.activity_portrait_capture)
        val barcodeView = findViewById<DecoratedBarcodeView>(R.id.zxing_barcode_scanner)

        // Hide default legacy status text to maintain clean Cyber-Security UI
        barcodeView.statusView?.visibility = View.GONE

        // Back button to close scanner
        val btnBack = findViewById<ImageButton>(R.id.btn_scanner_back)
        btnBack?.setOnClickListener { finish() }

        // Torch / Flashlight toggle
        val btnTorch = findViewById<ImageButton>(R.id.btn_torch)
        btnTorch?.setOnClickListener {
            if (isTorchOn) {
                barcodeView.setTorchOff()
                isTorchOn = false
                btnTorch.alpha = 0.7f
            } else {
                barcodeView.setTorchOn()
                isTorchOn = true
                btnTorch.alpha = 1.0f
            }
        }
        btnTorch?.alpha = 0.7f

        return barcodeView
    }
}
