package ru.myfinance

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue

class MainActivity : ComponentActivity() {
    // увеличивается при каждом возврате в приложение — чтобы перепроверить разрешения
    private var resumeTick by mutableIntStateOf(0)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AppTheme {
                // screen: "home" | "edit" | "settings"; editId = -1 для новой операции
                var screen by rememberSaveable { mutableStateOf("home") }
                var editId by rememberSaveable { mutableLongStateOf(-1L) }
                val home = { screen = "home" }

                when (screen) {
                    "edit" -> {
                        BackHandler(onBack = home)
                        EditScreen(id = editId.takeIf { it >= 0 }, onDone = home)
                    }
                    "settings" -> {
                        BackHandler(onBack = home)
                        SettingsScreen(resumeTick, onBack = home)
                    }
                    else -> HomeScreen(
                        resumeTick,
                        onAdd = { editId = -1; screen = "edit" },
                        onOpen = { editId = it; screen = "edit" },
                        onSettings = { screen = "settings" },
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        resumeTick++
    }
}
