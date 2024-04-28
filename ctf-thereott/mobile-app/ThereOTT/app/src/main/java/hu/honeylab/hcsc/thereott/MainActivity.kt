package hu.honeylab.hcsc.thereott

import android.annotation.SuppressLint
import android.os.Bundle
import android.view.ViewGroup
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.viewinterop.AndroidView
import com.google.android.exoplayer2.ExoPlayer
import com.google.android.exoplayer2.MediaItem
import com.google.android.exoplayer2.Player
import com.google.android.exoplayer2.ui.StyledPlayerView
import hu.honeylab.hcsc.thereott.ui.theme.ThereOTTTheme
import kotlinx.coroutines.*
import okhttp3.*
import org.apache.http.conn.ConnectTimeoutException
import java.io.IOException
import java.net.ConnectException
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class MainActivity : ComponentActivity() {
    private val baseUrls = arrayOf(
        "http://10.10.1.11:7385",
        "http://10.10.2.11:7385",
        "http://10.10.3.11:7385",
        "http://10.10.4.11:7385",
        "http://10.10.5.11:7385",
        "http://10.10.6.11:7385",
        "http://10.10.7.11:7385",
        "http://10.10.8.11:7385",
        "http://10.10.9.11:7385",
    ) // tailored to the CTF environment, update as needed
    private val videoPath = "/api/video.mp4"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            ThereOTTTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AppContent()
                }
            }
        }
    }

    private fun getRandomBaseUrl(): String {
        return baseUrls.random()
    }

    @SuppressLint("UnusedMaterial3ScaffoldPaddingParameter")
    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun AppContent() {
        val scope = rememberCoroutineScope()
        val context = LocalContext.current
        val baseUrl = getRandomBaseUrl()
        val player = remember { ExoPlayer.Builder(context).build() }
        var isLoading by remember { mutableStateOf(true) }
        var error by remember { mutableStateOf<String?>(null) }

        LaunchedEffect(true) {
            val timestamp = System.currentTimeMillis().toString()
            val signature = UtilsJNI.genSignature(
                "GET",
                videoPath,
                "",
                "x-tott-app-id:hu.honeylab.hcsc.thereott,x-tott-app-name:thereott",
                "",
                timestamp
            )
            val url = "$baseUrl$videoPath"

            try {
                val response = performNetworkRequest(url, timestamp, signature)
                val mediaItem = MediaItem.fromUri(response)
                player.setMediaItem(mediaItem)
                player.prepare()
                player.play()
                isLoading = false

                player.addListener(object : Player.Listener {
                    override fun onPlaybackStateChanged(state: Int) {
                        if (state == Player.STATE_ENDED) {
                            scope.launch {
                                val newUrl = "$baseUrl$videoPath"
                                try {
                                    val newResponse = performNetworkRequest(newUrl, timestamp, signature)
                                    val newMediaItem = MediaItem.fromUri(newResponse)
                                    player?.setMediaItem(newMediaItem)
                                    player?.prepare()
                                    player?.play()
                                } catch (e: Exception) {
                                    error = "Error loading video: ${e.message}"
                                }
                            }
                        }
                    }
                })
            } catch (e: Exception) {
                error = "Error loading video: ${e.message}"
                isLoading = false
            }
        }

        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(text = "ThereOTT") }
                )
            },
        ) {
            if (isLoading) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }
            } else {
                if (error != null) {
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(text = error!!)
                    }
                } else {
                    PlayerViewContainer(player)
                }
            }
        }
    }

    @Composable
    fun PlayerViewContainer(player: ExoPlayer) {
        AndroidView(
            factory = { ctx ->
                StyledPlayerView(ctx).apply {
                    setPlayer(player)
                    requestLayout()
                    invalidate()
                    layoutParams = ViewGroup.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.MATCH_PARENT
                    )
                }
            },
            update = { view ->
                view.player = player
            }
        )
    }



    private suspend fun performNetworkRequest(url: String, timestamp: String, signature: String): String {
        return suspendCancellableCoroutine { continuation ->
            val client = OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .build()

            val request = Request.Builder()
                .url(url)
                .header("x-timestamp", timestamp)
                .header("x-signature", signature)
                .header("x-tott-app-id", "hu.honeylab.hcsc.thereott")
                .header("x-tott-app-name", "ThereOtt")
                .build()

            val call = client.newCall(request)
            call.enqueue(object : Callback {
                override fun onResponse(call: Call, response: Response) {
                    val responseBody = response.body?.string() ?: ""
                    if (response.isSuccessful) {
                        continuation.resume(responseBody)
                    } else {
                        continuation.resumeWithException(IOException("Unexpected code $response $responseBody"))
                    }
                }

                override fun onFailure(call: Call, e: IOException) {
                    if (!continuation.isCancelled) {
                        if (e is ConnectException) {
                            continuation.resumeWithException(IOException("Failed to connect to server"))
                        } else if (e is ConnectTimeoutException) {
                            continuation.resumeWithException(IOException("Connection timed out"))
                        }
                        else {
                            continuation.resumeWithException(e)
                        }
                    }
                }
            })

            continuation.invokeOnCancellation {
                call.cancel()
            }
        }
    }


    @Preview(showBackground = true)
    @Composable
    fun AppPreview() {
        ThereOTTTheme {
            AppContent()
        }
    }
}
