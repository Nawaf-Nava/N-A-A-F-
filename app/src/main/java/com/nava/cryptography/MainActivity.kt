package com.nava.cryptography

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    var tabIndex by remember { mutableStateOf(0) }
                    Column {
                        TabRow(selectedTabIndex = tabIndex) {
                            Tab(selected = tabIndex == 0, onClick = { tabIndex = 0 }, text = { Text("تشفير") })
                            Tab(selected = tabIndex == 1, onClick = { tabIndex = 1 }, text = { Text("فك التشفير") })
                        }
                        // [Tab content implementation]
                    }
                }
            }
        }
    }
}
