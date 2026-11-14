package app.reczi.pgp

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Bitmap
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.os.Handler
import android.os.Looper
import android.util.Size
import android.view.Surface
import android.view.TextureView
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import app.reczi.pgp.core.Qr
import java.util.concurrent.Executors

/**
 * Lê um código QR com a câmara traseira, dentro de um diálogo. As imagens da câmara nunca são
 * guardadas: só passam pelo leitor de QR, em memória. Quem chama já confirmou a permissão da câmara.
 *
 * [accept] recebe cada código lido (fora da thread principal) e devolve se já está tudo lido e
 * uma indicação para mostrar. Enquanto não estiver, continua a ler: é assim que se leem as várias
 * partes de uma chave grande, uma a seguir à outra.
 */
class QrScanner(
    private val activity: Activity,
    private val title: String,
    private val accept: (String) -> Pair<Boolean, String>,
    private val onPhoto: () -> Unit,
    private val onDone: () -> Unit,
) {
    private val main = Handler(Looper.getMainLooper())
    private val decoder = Executors.newSingleThreadExecutor()
    private val preview = TextureView(activity)
    private val hint = TextView(activity)
    private var camera: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var dialog: AlertDialog? = null
    private var closed = false
    private var busy = false

    fun show() {
        val pad = (16 * activity.resources.displayMetrics.density).toInt()
        val width = minOf(activity.resources.displayMetrics.widthPixels, activity.resources.displayMetrics.heightPixels) - 6 * pad
        hint.text = "Aponta para o código QR. Mantém-no inteiro dentro da imagem e bem iluminado."
        hint.setPadding(0, 0, 0, pad / 2)
        val frame = FrameLayout(activity)
        frame.addView(preview, FrameLayout.LayoutParams(width, width * 4 / 3))
        val box = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, 0)
            addView(hint)
            addView(frame, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        }
        dialog = AlertDialog.Builder(activity).setTitle(title).setView(box)
            .setNegativeButton("Cancelar", null)
            .setNeutralButton("De uma fotografia…") { _, _ -> onPhoto() }
            .setOnDismissListener { close() }
            .create().also {
                it.window?.setFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE, android.view.WindowManager.LayoutParams.FLAG_SECURE)
                it.show()
            }
        preview.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(st: SurfaceTexture, w: Int, h: Int) = open(st)
            override fun onSurfaceTextureSizeChanged(st: SurfaceTexture, w: Int, h: Int) {}
            override fun onSurfaceTextureDestroyed(st: SurfaceTexture): Boolean { close(); return true }
            override fun onSurfaceTextureUpdated(st: SurfaceTexture) {}
        }
    }

    private fun fail(e: Throwable?) {
        if (closed) return
        hint.text = "Não foi possível usar a câmara (${e?.javaClass?.simpleName ?: "sem câmara traseira"}). " +
            "Tira uma fotografia ao código com a app da câmara e usa \"De uma fotografia…\"."
    }

    private fun open(texture: SurfaceTexture) {
        try {
            val manager = activity.getSystemService(Activity.CAMERA_SERVICE) as CameraManager
            val id = manager.cameraIdList.firstOrNull {
                manager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK
            } ?: manager.cameraIdList.firstOrNull() ?: return fail(null)
            val sizes = manager.getCameraCharacteristics(id).get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
                ?.getOutputSizes(SurfaceTexture::class.java)?.toList().orEmpty()
            // Formato 4:3 (como a área de pré-visualização), o maior que não passe de ~2 megapíxeis.
            val size = sizes.filter { it.width * 3 == it.height * 4 && it.width <= 1640 }.maxByOrNull { it.width }
                ?: sizes.filter { it.width <= 1920 }.maxByOrNull { it.width } ?: Size(1280, 960)
            texture.setDefaultBufferSize(size.width, size.height)
            val surface = Surface(texture)
            manager.openCamera(id, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    if (closed) return device.close()
                    camera = device
                    try {
                        val request = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                            addTarget(surface)
                            set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                        }
                        @Suppress("DEPRECATION")
                        device.createCaptureSession(listOf(surface), object : CameraCaptureSession.StateCallback() {
                            override fun onConfigured(s: CameraCaptureSession) {
                                if (closed) return
                                session = s
                                try { s.setRepeatingRequest(request.build(), null, main) } catch (e: Exception) { return fail(e) }
                                main.postDelayed(::tick, 500)
                            }
                            override fun onConfigureFailed(s: CameraCaptureSession) = fail(null)
                        }, main)
                    } catch (e: Exception) {
                        fail(e)
                    }
                }
                override fun onDisconnected(device: CameraDevice) { device.close(); camera = null }
                override fun onError(device: CameraDevice, error: Int) { device.close(); camera = null; fail(null) }
            }, main)
        } catch (e: SecurityException) {
            fail(e)
        } catch (e: Exception) {
            fail(e)
        }
    }

    /** De ~3 em 3 décimos de segundo, passa a imagem atual pelo leitor de QR (fora da thread principal). */
    private fun tick() {
        if (closed) return
        if (!busy && preview.isAvailable) {
            val bmp: Bitmap? = try { preview.bitmap } catch (e: Throwable) { null }
            if (bmp != null) {
                busy = true
                decoder.execute {
                    val text = try { decodeBitmap(bmp) } catch (e: Throwable) { null }
                    bmp.recycle()
                    val step = text?.let { runCatching { accept(it) }.getOrNull() }
                    main.post {
                        busy = false
                        if (closed) return@post
                        if (step?.first == true) { dialog?.dismiss(); onDone() }
                        else if (step != null) hint.text = step.second
                    }
                }
            }
        }
        main.postDelayed(::tick, 300)
    }

    private fun close() {
        if (closed) return
        closed = true
        main.removeCallbacksAndMessages(null)
        runCatching { session?.close() }
        runCatching { camera?.close() }
        decoder.shutdown()
    }

    companion object {
        /** Lê um QR de uma imagem; reduz as muito grandes para o leitor não ficar sem memória. */
        fun decodeBitmap(source: Bitmap): String? {
            val max = 1600
            val scale = maxOf(source.width, source.height).toFloat() / max
            val bmp = if (scale > 1f) Bitmap.createScaledBitmap(source, (source.width / scale).toInt(), (source.height / scale).toInt(), true) else source
            val pixels = IntArray(bmp.width * bmp.height)
            bmp.getPixels(pixels, 0, bmp.width, 0, 0, bmp.width, bmp.height)
            val text = Qr.decode(pixels, bmp.width, bmp.height)
            if (bmp !== source) bmp.recycle()
            return text
        }

        /** Desenha os módulos de um QR num bitmap com [size] píxeis de lado (aprox.). */
        fun render(modules: Array<BooleanArray>, size: Int): Bitmap {
            val n = modules.size
            val scale = maxOf(1, size / n)
            val bmp = Bitmap.createBitmap(n * scale, n * scale, Bitmap.Config.RGB_565)
            val row = IntArray(n * scale)
            for (y in 0 until n) {
                for (x in 0 until n) row.fill(if (modules[y][x]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt(), x * scale, (x + 1) * scale)
                for (dy in 0 until scale) bmp.setPixels(row, 0, n * scale, 0, y * scale + dy, n * scale, 1)
            }
            return bmp
        }
    }
}
